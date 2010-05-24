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
class DummyFuzzClient < FuzzClient
    def deliver(data,msg_id)
		["success",""]
    end
end

server="192.168.122.1"
DummyFuzzClient.setup(
    'server_ip'=>server,
    'work_dir'=>'.',
    'debug'=>false,
    'queue_name'=>'word'
)
EM.set_max_timers(1_000_000)
EventMachine::run {
    EM.add_periodic_timer( 10 ) do
        DummyFuzzClient.inspect_queues
        print "Timers #{EM.instance_variable_get(:@timers).size}"
    end
    EventMachine::connect(DummyFuzzClient.server_ip,DummyFuzzClient.server_port, DummyFuzzClient)
}
puts "Event loop stopped. Shutting down."
