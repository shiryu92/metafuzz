require 'rubygems'
require File.dirname(__FILE__) + '/../core/fuzzer_new'
require 'trollop'


# This is a dumb fuzzer which doesn't even unpack the OLE file
# It's the simplest use of my fuzzer class / algorithms
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class Producer < Generators::NewGen

    def initialize( args, prodclient_klass )
        @opts=Trollop::options( args ) do
            opt :granularity, "Granularity - number of fields to cut file into", :type=>:integer, :default=>128
            opt :template, "Template filename", :type=>:string, :required=>true
        end
        @template=File.open( @opts[:template] ,"rb") {|io| io.read}
        our_tag=""
        our_tag << "ROLLINGCORRUPT_GRANULARITY:#{@opts[:granularity]}\n"
        our_tag << "ROLLINGCORRUPT_TEMPLATE:#{@opts[:template]}\n"
        our_tag << "ROLLINGCORRUPT_TEMPLATE_MD5:#{Digest::MD5.hexdigest(@template)}\n"
        prodclient_klass.base_tag=prodclient_klass.base_tag << our_tag
        @duplicate_check=Hash.new(false)
        @fuzztarget=Fuzzer.string_to_binstruct( @template.clone, granularity, endian=:little )
        @block=Fiber.new do
            fuzzer=Fuzzer.new( @fuzztarget )
            fuzzer.verbose=false
            fuzzer.basic_tests(10000,false,0,2) {|fuzz|
                Fiber.yield fuzz.to_s
            }
            false
        end
        super
    end
end
