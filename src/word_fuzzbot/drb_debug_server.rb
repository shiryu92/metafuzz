require File.dirname(__FILE__) + '/../core/connector'
require File.dirname(__FILE__) + '/conn_office'
require File.dirname(__FILE__) + '/conn_cdb'
require 'rubygems'
require 'trollop'
require 'drb'

OPTS=Trollop::options do
    opt :port, "Port to listen on, default 8888", :type=>:integer, :default=>8888
end

class DebugServer

    def start_debugger( *args )
        @this_debugger=Connector.new(CONN_CDB, *args)
        @subserver=DRb.start_service( nil, @this_debugger )
        @subserver.uri
    end

    def close_debugger
        @this_debugger.close
        @subserver.stop_service
    end

end

trap(21) {
    # CTRL_BREAK - Ignore
}

DRb.start_service( "druby://127.0.0.1:#{OPTS[:port]}", DebugServer.new )
DRb.thread.join
