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
        @debugger_conn=Connector.new( CONN_CDB, *args )
        true
    end

    def close_debugger
        @debugger_conn.close
        true
    end

    def shim( meth, *args )
        @debugger_conn.send( meth, *args )
    end

end

trap(21) {
    # CTRL_BREAK - Ignore
}

DRb.start_service( "druby://127.0.0.1:#{OPTS[:port]}", DebugServer.new )
DRb.thread.join
