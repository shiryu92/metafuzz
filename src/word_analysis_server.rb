require File.dirname(__FILE__) + '/analysis_server'
require File.dirname(__FILE__) + '/analysis_fsconn'
require 'base64'

# Fairly basic adaptation of the AnalysisServer class to handle Word fuzzing. 
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


# Anything not set up here gets the default value. Uses the new 1.9 hash syntax.

EM.epoll
EventMachine::run {
    AnalysisServer.setup 'db_password'=>'YtQ%m31337', 'debug'=>true
    EventMachine::start_server(AnalysisServer.server_ip, AnalysisServer.server_port, AnalysisServer)
}
