require 'xmlrpc/server'
require 'fuzzer'
require 'base64'

class DistFuzz
    INTERFACE = XMLRPC::interface("fuzz") {
        meth 'int new_fuzzer(str)', 'New fuzzer from string', 'new_fuzzer'
        meth 'str next_case(int)', 'Next case for fuzzer_id', 'next_case'
        meth 'void close_fuzzer(int)','Shutdown fuzzer_id', 'close_fuzzer'
    }

    def initialize
        @fuzzer_count=0
        @fuzzers={}
    end

    def new_fuzzer( template_string )
        @fuzzer_count+=1
        this_fuzzer=Fuzzer.new(template_string)
        this_fuzzer.preserve_length=true
        # Store an Enumerator
        e=this_fuzzer.enum_for(:basic_tests)
        @fuzzers[@fuzzer_count]=e
        @fuzzer_count
    end

    def next_case( fuzzer_id )
        # This will raise StopIteration at some point
        # which will get passed down to the client
        test_case=@fuzzers[fuzzer_id].next.to_s
        Base64::encode64( test_case )
    end

    def close_fuzzer( fuzzer_id )
    end

end

server=XMLRPC::Server.new(7755, "0.0.0.0")
server.add_handler( DistFuzz::INTERFACE, DistFuzz.new)
server.serve

