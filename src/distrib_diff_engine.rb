require 'xmlrpc/server'
require 'xmlrpc/marshal'
require 'yaml'
require 'diff_engine'
require 'grammar'

class DiffBroker
    INTERFACE = XMLRPC::interface("db") {
        meth 'int setup_diff_engine(str)', 'Setup the diff engine', 'setup_diff_engine'
        meth 'str shim(int, str, str)', 'Shim method.', 'shim'
    }
    def initialize
        @diff_engines={}
    end

    def shim( diff_engine_filename, method_name, arg_array)
        begin
            YAML.dump(@diff_engines[diff_engine_filename].send(method_name, *(YAML.load(arg_array))))
        rescue
            puts $!
            p arg_array
            raise ArgumentError, "#{$!}"
        end
    end

    def setup_diff_engine( grammar_filename )
        begin
            unless @diff_engines[grammar_filename]
                g=Grammar.new( grammar_filename)
                de=DiffEngine.new(g)
                @diff_engines[grammar_filename]=de
            end
            g.size
        rescue
            raise ArgumentError, "#{$!}"
        end
    end
end

server=XMLRPC::Server.new(8888, "0.0.0.0")
server.add_handler( DiffBroker::INTERFACE, DiffBroker.new)
server.serve

