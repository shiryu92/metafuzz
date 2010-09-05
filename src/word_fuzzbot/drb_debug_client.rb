require 'rubygems'
require 'drb'

class DebugClient

    def initialize( addr, port )
        @debug_server=DRbObject.new nil, "druby://#{addr}:#{port}"
    end

    def start_debugger( *args )
        # Return the URI
        @debug_server.start_debugger( *args )
    end

    def close_debugger
        @debug_server.close_debugger
    end

end
