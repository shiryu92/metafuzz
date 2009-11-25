require 'fuzz_server_new'
require 'base64'

# Fairly basic adaptation of the FuzzServer class to handle Word fuzzing. 
# All I'm doing is overloading the handle_result method to write stuff
# out with a .doc extension.
#
# Revised version, using v2 of the fuzzprotocol.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

class WordFuzzServer < FuzzServer
end

# Anything not set up here gets the default value.
WordFuzzServer.setup 'debug'=>false, 'poll_interval'=>60

EM.epoll
EM.set_max_timers(5000)
EventMachine::run {
    # Dump some status info every now and then using leet \r style.
EM.set_quantum 10
    EM.add_periodic_timer(20) do 
        @summary=WordFuzzServer.lookup[:summary]
        @old_time||=Time.now
        @old_total||=@summary['total']
        @total=@summary['total']
        #print "\rconns: #{EventMachine.connection_count}, "
        print "\rQ: #{WordFuzzServer.queue[:ready_fuzzclients].size}, "
        print "Done: #{@total} ("
        print "S/F/C: #{@summary['success']} / "
        print "#{@summary['fail']} / "
        print "#{@summary['crash']}), "
        print "Speed: #{"%.2f" % ((@total-@old_total)/(Time.now-@old_time).to_f)}   "
        @old_total=@summary['total']
        @old_time=Time.now
    end
EventMachine::start_server(WordFuzzServer.listen_ip, WordFuzzServer.listen_port, WordFuzzServer)
}
