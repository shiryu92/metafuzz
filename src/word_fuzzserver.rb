require 'fuzz_server'
require 'base64'

# Fairly basic adaptation of the FuzzServer class to handle Word fuzzing. 
# All I'm doing is overloading the handle_result method to write stuff
# out with a .doc extension.
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

class WordFuzzServer < FuzzServer
    # handle the result, write out the doc file and the .txt details.
    # Create a 5 letter salt, so crashes don't clobber each other...
    Salt=Array.new(5).map {|e| (0x41+rand(26)).chr}.join
    def handle_result( msg )
        result_id,result_status,crashdata,crashfile=msg.id, msg.status, msg.data, msg.crashfile
        if result_status=='crash'
            detail_path=File.join(self.class.work_dir,"detail-#{Salt}-#{result_id}.txt")
            crashfile_path=File.join(self.class.work_dir,"crash-#{Salt}-#{result_id}.doc")
            File.open(detail_path, "wb+") {|io| io.write(crashdata)}
            # TODO: now that the protocol supports optional encoding, need to fix this
            # in case we decode unencoded data...
            File.open(crashfile_path, "wb+") {|io| io.write(Base64::decode64(crashfile))}
        end
        self.class.result_tracker.add_result(Integer(result_id),result_status,detail_path||=nil,crashfile_path||=nil)
        self.class.delayed_result_queue.select {|dr| dr.server_id==msg.id}.each {|dr| 
            dr.send_result(result_status)
            self.class.delayed_result_queue.delete dr
        }
    end
end

# Anything not set up here gets the default value. Uses the new 1.9 hash syntax.
WordFuzzServer.setup work_dir: "/fuzzfiles"

EM.epoll
EventMachine::run {
    # Dump some status info every now and then using leet \r style.
    EM.add_periodic_timer(20) do 
    @old_time||=Time.now
    @old_total||=Integer(WordFuzzServer.result_tracker.summary[:current_count])
    @total=Integer(WordFuzzServer.result_tracker.summary[:current_count])
    #print "\rconns: #{EventMachine.connection_count}, "
    print "\rQ: #{WordFuzzServer.waiting_for_data.size}, "
    print "Done: #{@total} ("
    print "S/F/C: #{WordFuzzServer.result_tracker.summary[:success]} / "
    print "#{WordFuzzServer.result_tracker.summary[:fail]} / "
    print "#{WordFuzzServer.result_tracker.summary[:crash]}), "
    print "Speed: #{"%.2f" % ((@total-@old_total)/(Time.now-@old_time).to_f)}   "
    @old_total=Integer(WordFuzzServer.result_tracker.summary[:current_count])
    @old_time=Time.now
    end
EventMachine::start_server(WordFuzzServer.server_ip, WordFuzzServer.server_port, WordFuzzServer)
}
