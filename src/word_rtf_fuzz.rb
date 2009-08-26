require 'rubygems'
require 'fuzzer'

class Producer < Generators::NewGen

    SEEN_LIMIT=5000
    Template=File.open( File.expand_path("~/fuzzserver/template.rtf"),"rb") {|io| io.read}

    def seen?( str )
        hsh=Digest::MD5.hexdigest(str)
        seen=@duplicate_check[hsh]
        @duplicate_check[hsh]=true
        @duplicate_check.shift if @duplicate_check.size > SEEN_LIMIT
        seen
    end

    def initialize
        @duplicate_check=Hash.new(false)
        @block=Fiber.new do
            loop do
                struct=Fuzzer.string_to_binstruct(Template.clone,128,:little)
                fuzzer=Fuzzer.new(struct)
		fuzzer.verbose=false
                fuzzer.basic_tests(10000,false,0,2) {|test|
                    next if seen? test.to_s
                    Fiber.yield test.to_s
                }
            end
            false
        end
        super
    end
end

