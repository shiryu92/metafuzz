require 'rubygems'
require 'msgpack/rpc'

class DebugClient

    def initialize( addr, port )
        @debugger_conn=::MessagePack::RPC::Client.new( addr, port )
    end

    def start_debugger( *args )
        @args=args
        @debugger_conn.call :start_debugger, *args
    end

    def close_debugger
        @debugger_conn.call :close_debugger
    end

    def target_pid
        @debugger_conn.call :shim, :target_pid
    end

    def debugger_pid
        @debugger_conn.call :shim, :debugger_pid
    end

    def puts( str )
        @debugger_conn.call :shim, :puts, str
    end

    def qc_all
        @debugger_conn.call :shim, :qc_all
    end

    def dq_all
        @debugger_conn.call :shim, :dq_all
    end

    def registers
        @debugger_conn.call :shim, :registers
    end

    def send_break
        @debugger_conn.call :shim, :send_break
    end

    def target_running?
        @debugger_conn.call :shim, :target_running?
    end

    def sync
        @debugger_conn.call :shim, :sync
    end

    def destroy_server
        @debugger_conn.call :destroy
    end

end
