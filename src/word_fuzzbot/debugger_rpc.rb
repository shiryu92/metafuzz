require File.dirname(__FILE__) + '/../core/connector'
require File.dirname(__FILE__) + '/conn_office'
require File.dirname(__FILE__) + '/conn_cdb'
require 'rubygems'
require 'msgpack/rpc'

class DebugServer

    def new_debugger( *args )
        @debugger_conn.close rescue nil
        @debugger_conn=Connector.new( CONN_CDB, *args )
        true
    end

    def close_debugger
        @debugger_conn.close rescue nil
    end

    def shim( meth, *args )
        @debugger_conn.send( meth, *args )
    end

end

server=MessagePack::RPC::Server.new
server.listen('127.0.0.1', 8888, DebugServer.new)
server.run


    
