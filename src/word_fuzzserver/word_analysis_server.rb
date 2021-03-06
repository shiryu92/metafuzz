require File.dirname(__FILE__) + '/../analysis_tools/analysis_server'
require File.dirname(__FILE__) + '/../analysis_tools/analysis_fsconn'
require 'base64'
require 'trollop'

OPTS = Trollop::options do 
    opt :crash_dir, "Directory to use for crash files and detail files", :type => :string, :required=>true
    opt :debug, "Turn on debug mode", :type => :boolean
end

# Fairly basic adaptation of the AnalysisServer class to handle Word fuzzing. 
# All I'm doing is overloading the handle_result method to write stuff
# out with a .doc extension.
#
# Revised version, using v3 of the fuzzprotocol.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt



EM.set_max_timers(1000000)
EM.epoll
EventMachine::run {
    # Anything not set up here gets the default value.
    AnalysisServer.setup( 'debug'=>OPTS[:debug] )
    FuzzServerConnection.setup( 'work_dir'=>OPTS[:crash_dir], 'debug'=>OPTS[:debug] )
    EventMachine::start_server(AnalysisServer.listen_ip, AnalysisServer.listen_port, AnalysisServer)
}
