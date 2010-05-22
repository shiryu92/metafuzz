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
require File.dirname(__FILE__) + '/conn_office'
require File.dirname(__FILE__) + '/conn_cdb'
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
		["success",""]
    end
end

server="192.168.22.1"
WordFuzzClient.setup(
    'server_ip'=>server,
    'work_dir'=>'R:/fuzzclient',
    'debug'=>false,
    'poll_interval'=>60,
    'queue_name'=>'word'
)

EventMachine::run {
    system("start ruby wordslayer.rb")
    system("start ruby dk.rb")
    EventMachine::connect(WordFuzzClient.server_ip,WordFuzzClient.server_port, WordFuzzClient)
}
puts "Event loop stopped. Shutting down."
