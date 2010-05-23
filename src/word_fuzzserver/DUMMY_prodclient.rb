require 'rubygems'
require File.dirname(__FILE__) + '/../core/fuzzer_new'
require 'trollop'

OPTS = Trollop::options do 
    opt :size, "Size of tests in KB", :type => :integer, :required => true
end

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

    Template=("A" * (OPTS[:size] * 1024))

    def initialize
        @duplicate_check=Hash.new(false)
        @block=Fiber.new do
            loop do
            # This will just send the template over and over. 
            # To actually fuzz, make changes and yield at each step.
            Fiber.yield Template
            end
            false
        end
        super
    end
end
