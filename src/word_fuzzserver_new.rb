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
    # handle the result, write out the doc file and the .txt details.
    # Create a 5 letter salt, so crashes don't clobber each other...
    Salt=Array.new(5).map {|e| (0x41+rand(26)).chr}.join
    def handle_result( msg )
        result_id,result_status,crashdata,crashfile=msg.id, msg.status, msg.data, msg.crashfile
        if result_status=='crash'
            # paranoia, but we don't want to lose crashes.
            detail_path=File.join(self.class.work_dir,"detail-#{Salt}-#{result_id}.txt")
            crashfile_path=File.join(self.class.work_dir,"crash-#{Salt}-#{result_id}.doc")
            File.open(detail_path, "wb+") {|io| io.write(crashdata)}
            File.open(crashfile_path, "wb+") {|io| io.write(Base64::decode64(crashfile))}
        end
        # The main class method will send to the DB etc
        super
    end
end

# Anything not set up here gets the default value. Uses the new 1.9 hash syntax.
WordFuzzServer.setup work_dir: "/fuzzfiles"

EM.epoll
EventMachine::run {
    EventMachine::start_server(WordFuzzServer.server_ip, WordFuzzServer.server_port, WordFuzzServer)
}
