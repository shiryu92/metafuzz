require 'xmlrpc/client'
require 'yaml'
require 'diff_engine'
require 'grammar'

class DiffBrokerClient

    TIMEOUT=12000 

    def initialize( ip, port, grammar_filename, timeout=nil )
        @conn=XMLRPC::Client.new2("http://#{ip}:#{port}")
        @conn.timeout=timeout || TIMEOUT
        @grammar_filename=grammar_filename
        @conn.call( "db.setup_diff_engine", grammar_filename )
    rescue XMLRPC::FaultException => e
        puts "Error:"
        puts e.faultCode
        puts e.faultString
    end

    def method_missing( meth, *args )
        YAML.load(@conn.call("db.shim", @grammar_filename, String( meth ), YAML.dump(args)))
    rescue XMLRPC::FaultException => e
        puts "Error:"
        puts e.faultCode
        puts e.faultString
    end

end
