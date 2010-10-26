require File.dirname(__FILE__) + '/../core/connector'
require File.dirname(__FILE__) + '/conn_cdb'
require 'rubygems'
require 'msgpack/rpc'
require 'trollop'

OPTS=Trollop::options do
    opt :port, "Port to listen on, default 8888", :type=>:integer, :default=>8888
    opt :debug, "Debug output", :type=>:boolean
end

class DebugServer

    COMPONENT="MsgpackDebugServer"
    VERSION="1.5.0"

    def start_debugger( *args )
        @debugger_conn=Connector.new( CONN_CDB, *args )
        warn "#{COMPONENT}:#{VERSION}: Started #{@debugger_conn.debugger_pid} for #{args[0]['pid']}" if OPTS[:debug]
        true
    end

    def close_debugger
        @debugger_conn.close if @debugger_conn
        warn "#{COMPONENT}:#{VERSION}: Closing #{@debugger_conn.debugger_pid rescue "<no debugger>"}" if OPTS[:debug]
        true
    end

    def shim( meth, *args )
        warn "#{COMPONENT}:#{VERSION}: Shimming #{meth}" if OPTS[:debug]
        @debugger_conn.send( meth, *args )
    end

    def destroy
        begin
            warn "#{COMPONENT}:#{VERSION}: Received destroy. Exiting." if OPTS[:debug]
            close_debugger rescue nil
        rescue
            puts $!
        ensure
            Process.exit!
        end
    end

end

server=MessagePack::RPC::Server.new
server.listen('127.0.0.1', OPTS[:port], DebugServer.new)
server.run
