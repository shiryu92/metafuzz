require 'rubygems'
require 'trollop'
require File.dirname(__FILE__) + '/../core/fuzzer_new'


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

    def initialize( args, prodclient_klass )
        @opts=Trollop::options( args ) do
            opt :template, "Template filename", :type=>:string, :required=>true
        end
        @template=File.open( @opts[:template] ,"rb") {|io| io.read}
        our_tag=""
        our_tag << "DUMMY_TEMPLATE:#{@opts[:template]}\n"
        our_tag << "DUMMY_TEMPLATE_MD5:#{Digest::MD5.hexdigest(@template)}\n"
        prodclient_klass.base_tag=prodclient_klass.base_tag << our_tag
        @block=Fiber.new do
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
