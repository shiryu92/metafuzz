# This is a bit of a mishmash - if you set up your fuzzclients correctly you can skip a
# lot of the commands and stuff. The main thing this class
# does is overload the deliver method in the FuzzClient class to do the Word specific
# delivery stuff.  This is the key file that would have to be rewritten to change fuzzing
# targets.
#
# In my setup, this file is invoked by a batch script that runs at system startup, and
# copies the neccessary scripts from a share, so to upgrade this code you can just change
# the shared copy and reboot all your fuzzclients.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

require File.dirname(__FILE__) + '/../core/fuzz_client_new'
require File.dirname(__FILE__) + '/../core/connector'
require 'conn_office'
require 'conn_cdb'
require 'win32/registry'

# Clear the registry keys that remember crash files at the start of each run. Thus, not a
# bad idea to reboot every week or two, so this script will restart.
begin
    Win32::Registry::HKEY_CURRENT_USER.open('SOFTWARE\Microsoft\Office\12.0\Word\Resiliency',Win32::Registry::KEY_WRITE) do |reg|
        reg.delete_key "StartupItems" rescue nil
        reg.delete_key "DisabledItems" rescue nil
    end
rescue
    nil
end

# Temporary sets of commands and stuff go here. Lame, but working.

class WordFuzzClient < FuzzClient

    def prepare_test_file(data, msg_id)
        begin
            filename="test-"+msg_id.to_s+".doc"
            path=File.join(self.class.work_dir,filename)
            File.open(path, "wb+") {|io| io.write data}
            path
        rescue
            raise RuntimeError, "Fuzzclient: Couldn't create test file #{filename} : #{$!}"
        end
    end

    def clean_up( fn )
        10.times do
            begin
                FileUtils.rm_f(fn)
            rescue
                raise RuntimeError, "Fuzzclient: Failed to delete #{fn} : #{$!}"
            end
            return true unless File.exist? fn
            sleep(0.1)
        end
        return false
    end

    def deliver(data,msg_id)
        begin
            status='error'
            crash_details="" # will only be set to anything if there's a crash
            this_test_filename=prepare_test_file(data, msg_id)
            @succeeded_before||=false
            unless @succeeded_before
                begin
                    5.times do
                        begin
                            @word=Connector.new(CONN_OFFICE, 'word')
                            break
                        rescue
                            sleep(1)
                            next
                        end
                    end
                rescue
                    raise RuntimeError, "Couldn't establish connection to app. #{$!}"
                end
                current_pid=@word.pid
                # Attach debugger
                # -snul - don't load symbols
                # -c  - initial command
                # sxe -c "!exploitable -m;g" av - run the MS !exploitable windbg extension
                # -pb don't request an initial break (not used now, cause we need the break so we can read the initial command)
                # -xi ld ignore module loads
                debugger=Connector.new(CONN_CDB,"-xi ld -p #{current_pid}")
                debugger.puts "!load winext\\msec.dll"
                debugger.puts ".sympath c:\\localsymbols"
                debugger.puts ".echo startup done"
                debugger.puts "sxe -c \"!exploitable -m;lm v;r;.echo xyzzy;g;qd\" av"
                debugger.puts "g"
            end
            begin
                @word.deliver this_test_filename
                # As soon as the deliver method doesn't raise an exception, we lose interest.
                status='success'
                print '.'
                @word.close_documents
                @succeeded_before=true
            rescue
                # check for crashes
                @succeeded_before=false
                sleep(0.1)
                if (details=debugger.qc_all.join)=~ /EXCEPTION_TYPE:STATUS_ACCESS_VIOLATION/
                    until crash_details=~/xyzzy/
                        crash_details << debugger.dq_all.join
                    end
                crash_details=crash_details.scan( /startup done(.*)xyzzy/m ).join
                if self.class.debug
                    filename="crash-"+msg_id.to_s+".txt"
                    path=File.join(self.class.work_dir,filename)
                    File.open(path, "wb+") {|io| io.write crash_details}
                end
                status='crash'
                print '!'
                else
                    status='fail'
                    print '#'
                    if self.class.debug
                        filename="noncrash-"+msg_id.to_s+".txt"
                        path=File.join(self.class.work_dir,filename)
                        File.open(path, "wb+") {|io| io.write crash_details}
                    end
                end
            end
            # close the debugger and kill the app
            # This should kill the winword process as well
            # Clean up the connection object
            unless @succeeded_before
                @word.close rescue nil
                debugger.close rescue nil
            end
            clean_up(this_test_filename) 
            [status,crash_details]
        rescue
            raise RuntimeError, "Delivery: fatal: #{$!}"
            # ask the server to revert me to my snapshot?
        end
    end
end

server="192.168.122.1"
WordFuzzClient.setup(
    'server_ip'=>server,
    'work_dir'=>'R:/fuzzclient',
    'debug'=>false,
    'poll_interval'=>60,
    'queue_name'=>'word'
)

EventMachine::run {
    system("start ruby wordslayer.rb")
    system("start ruby dialog_killer.rb")
    EventMachine::connect(WordFuzzClient.server_ip,WordFuzzClient.server_port, WordFuzzClient)
}
puts "Event loop stopped. Shutting down."
