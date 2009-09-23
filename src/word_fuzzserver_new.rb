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
WordFuzzServer.setup 'debug'=>true, 'poll_interval'=>60

EM.epoll
EventMachine::run {
    EventMachine::start_server(WordFuzzServer.server_ip, WordFuzzServer.server_port, WordFuzzServer)
}
