require 'rubygems'
require File.dirname(__FILE__) + '/../core/fuzzer_new'

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

    def initialize( template_fname, granularity=128)
        @template=File.open( template_fname ,"rb") {|io| io.read}
        @duplicate_check=Hash.new(false)
        @fuzztarget=Fuzzer.string_to_binstruct( @template.clone, granularity, endian=:little )
        @block=Fiber.new do
            fuzzer=Fuzzer.new( @fuzztarget )
            fuzzer.verbose=false
            f.basic_tests(10000,false,0,2) {|fuzz|
                Fiber.yield fuzz.to_s
            }
            false
        end
        super
    end
end
