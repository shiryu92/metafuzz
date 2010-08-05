require 'rubygems'
require File.dirname(__FILE__) + '/../core/fuzzer_new'
require 'trollop'

# This is a port of Charlie Miller's '5 lines of python' from his CSW 2010
# presentation.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class Producer < Generators::NewGen

    def initialize( args )
        SUBOPTS=Trollop::options(args) do
            opt :template, "Template filename", :string, :required=>true
            opt :fuzzfactor, "Fuzzfactor (% of bytes to corrupt)", :integer, :default=>10
        end
        @template=File.open( SUBOPTS[:template] ,"rb") {|io| io.read}
        @block=Fiber.new do
            loop do
                working_copy=@template.clone
                max_crap_bytes=(@template.length / SUBOPTS[:fuzzfactor] ).round
                (rand(max_crap_bytes)+1).times do
                    working_copy[rand(@template.length)]=rand(256).chr
                end
                Fiber.yield working_copy
            end
            false
        end
        super
    end

end
