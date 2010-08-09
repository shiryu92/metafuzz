# The main thing this class does is overload the deliver method in the FuzzClient class to 
# do the Word specific delivery stuff.  This is the key file that would have to be rewritten
# to change fuzzing targets.
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

class WordFuzzClient < FuzzClient
    VERSION="3.5.0"

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

    def deliver(data,msg_id,opts=[])
        begin
            status='error'
            crash_details="" # will only be set to anything if there's a crash
            this_test_filename=prepare_test_file(data, msg_id)
            @reuse_process||=false
            if opts.contains? "clean"
                @reuse_process=false
                @word.close rescue nil
                @debugger.close rescue nil
            end
            unless @reuse_process
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
                @debugger=Connector.new(CONN_CDB,"-xi ld -p #{current_pid}")
                @debugger.puts "!load winext\\msec.dll"
                @debugger.puts ".sympath c:\\localsymbols"
                @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy;.kill /n;g\" av"
                @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy;.kill /n;g\" sbo"
                @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy;.kill /n;g\" ii"
                @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy;.kill /n;g\" gp"
                @debugger.puts "sxi e0000001"
                @debugger.puts "sxi e0000002"
                @debugger.puts "g"
            end
            begin
                @word.deliver this_test_filename
                # As soon as the deliver method doesn't raise an exception, we lose interest.
                status='success'
                print '.'
                @word.close_documents
                @reuse_process=true
            rescue Exception=>e
                # check for crashes
                sleep(0.1)
                if (details=@debugger.qc_all.join) =~ /frobozz/
                    until crash_details=~/xyzzy/
                        crash_details << @debugger.dq_all.join
                    end
                    crash_details=crash_details.scan( /frobozz(.*)xyzzy/m ).join
                    if self.class.debug
                        filename="crash-"+msg_id.to_s+".txt"
                        path=File.join(self.class.work_dir,filename)
                        File.open(path, "wb+") {|io| io.write crash_details}
                    end
                    status='crash'
                    print '!'
                    @reuse_process=false
                else
                    status='fail'
                    print '#'
                    @reuse_process=@word.is_connected?
                    if self.class.debug
                        filename="noncrash-"+msg_id.to_s+".txt"
                        path=File.join(self.class.work_dir,filename)
                        File.open(path, "wb+") {|io|
                            io.puts e
                            io.puts e.backtrace
                            io.puts "------Debugger output------------------"
                            io.write details
                        }
                    end
                end
            end
            # Also re-open Word 1% of the time, to stop long running processes
            # from sucking up too much RAM and slowing down.
            if (@reuse_process==false) or (rand(100) > 98)
                # close the debugger and kill the app
                # This should kill the winword process as well
                # Clean up the connection object
                @word.close rescue nil
                @debugger.close rescue nil
                @reuse_process=false
            end
            clean_up(this_test_filename) 
            [status,crash_details]
        rescue
            raise RuntimeError, "Delivery: fatal: #{$!}"
            system("shutdown -r -f -t 0")
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
    system("start /HIGH ruby wordslayer.rb") # Better chance of killing memory hogs
    system("start ruby dialog_killer.rb")
    EventMachine::connect(WordFuzzClient.server_ip,WordFuzzClient.server_port, WordFuzzClient)
}
puts "Event loop stopped. Shutting down."
