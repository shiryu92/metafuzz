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

    def initialize( args, prodclient_klass )
        @opts=Trollop::options( args ) do
            opt :fuzzfactor, "Fuzzfactor: corrupts (len  / n)  bytes", :type=>:integer, :default=>10
            opt :template, "Template filename", :type=>:string, :required=>true
        end
        @template=File.open( @opts[:template] ,"rb") {|io| io.read}
        our_tag=""
        our_tag << "MILLERFUZZ_FUZZFACTOR:#{@opts[:fuzzfactor]}\n"
        our_tag << "MILLERFUZZ_TEMPLATE:#{@opts[:template]}\n"
        our_tag << "MILLERFUZZ_TEMPLATE_MD5:#{Digest::MD5.hexdigest(@template)}\n"
        p prodclient_klass
        p prodclient_klass.class
        prodclient_klass.base_tag=prodclient_klass.base_tag << our_tag
        @block=Fiber.new do
            loop do
                working_copy=@template.clone
                max_crap_bytes=(@template.length / @opts[:fuzzfactor] ).round
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
