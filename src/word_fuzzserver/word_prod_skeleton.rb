require 'rubygems'
require File.dirname(__FILE__) + '/../core/fuzzer'

# Skeleton for a Producer generator - this is the bit that actually does the case
# generation.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class Producer < Generators::NewGen

    def initialize( template_fname )
        @template=File.open( template_fname ,"rb") {|io| io.read}
        @duplicate_check=Hash.new(false)
        @block=Fiber.new do
            io=StringIO.new(@template.clone)
            @template.freeze
            loop do
                # This will just send the template over and over. 
                # To actually fuzz, make changes and yield at each step.
                Fiber.yield @template
            end
            false
        end
        super
    end
end
