require 'xmlrpc/server'
require 'xmlrpc/marshal'

class Gay
    INTERFACE = XMLRPC::interface("gay") {
        meth 'str gayify(str)', 'make a string gay', 'gayify'
    }

    def gayify( str )
        if rand > 0.75
            raise ArgumentError, "Not gay enough"
        else
            "ooOOooOOOOO!!! '#{str}', WELL! suits you sir!"
        end
    end
end

server=XMLRPC::Server.new(7755, "0.0.0.0")
server.add_handler( Gay::INTERFACE, Gay.new)
server.serve

