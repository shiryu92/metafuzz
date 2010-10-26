require 'rubygems'
require 'drb'

class DebugClient

    attr_reader :target_pid, :debugger_pid

    def initialize( addr, port )
        @debug_server=DRbObject.new nil, "druby://#{addr}:#{port}"
    end

    def start_debugger( *args )
        # Return the URI
        @debugger_pid, @target_pid, uri=@debug_server.start_debugger( *args )
        uri
    end

    def close_debugger
        @debug_server.close_debugger
    end

    def destroy_server
        @debug_server.destroy
    end

end
