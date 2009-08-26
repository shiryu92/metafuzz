require 'rubygems'
require 'fuzzer'
require 'generators'
require 'digest/md5'

# This is a working case generator for RTF (not a great one, but it still
# generates some crashes). All it does is look for integers and hexstring
# blobs, and messes with them. Because RTF is ASCII not packed binary I 
# need to jump through a few hoops since my generators are designed for
# packed data.
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class Producer < Generators::NewGen

    SEEN_LIMIT=5000
    Template=File.open( File.expand_path("~/fuzzserver/template.rtf"),"rb") {|io| io.read}
    attr_reader :encoding

    def seen?( str )
        hsh=Digest::MD5.hexdigest(str)
        seen=@duplicate_check[hsh]
        @duplicate_check[hsh]=true
        @duplicate_check.shift if @duplicate_check.size > SEEN_LIMIT
        seen
    end

    def base10_str_generator( str )
        if str.to_i < 65536
            # it fits in 16 bits
            packed=[str.to_i].pack('n')
            g1=Generators::RollingCorrupt.new(packed,16,16,16)
            g2=Generators::RollingCorrupt.new(packed,16,16,16)
            unpacker1=proc do |ary| ary.first.unpack('n').first.to_s end
            unpacker2=proc do |ary| "-" << ary.first.unpack('n').first.to_s end
            fixed1=Generators::Repeater.new(g1,1,1,1,unpacker1)
            fixed2=Generators::Repeater.new(g2,1,1,1,unpacker2)
            final=Generators::Chain.new(fixed1,fixed2)
        else
            # force it into 32 bits
            packed=[str.to_i].pack('N')
            g1=Generators::RollingCorrupt.new(packed,32,32,16)
            g2=Generators::RollingCorrupt.new(packed,32,32,16)
            unpacker1=proc do |ary| ary.first.unpack('N').first.to_s end
            unpacker2=proc do |ary| "-" << ary.first.unpack('N').first.to_s end
            fixed1=Generators::Repeater.new(g1,1,1,1,unpacker1)
            fixed2=Generators::Repeater.new(g2,1,1,1,unpacker2)
            final=Generators::Chain.new(fixed1,fixed2)
        end
    end

    def hexstring_generator( str )
        packed=[str].pack('H*')
        g1=Generators::RollingCorrupt.new(packed,16,16,32,:little)
        g2=Generators::RollingCorrupt.new(packed,15,5,16)
        g3=Generators::RollingCorrupt.new(packed,8,8,50)
        g4=Generators::RollingCorrupt.new(packed,32,32,32,:little)
        chained=Generators::Chain.new(g1,g2,g3,g4)
        unpacker=proc do |ary| ary.first.unpack('H*').first end
        final=Generators::Repeater.new(chained,1,1,1,unpacker)
    end

    def initialize
        @duplicate_check=Hash.new(false)
	@encoding='base64'
        @block=Fiber.new do
            # substrings can be 2+ hex digits, 1+ digit or none of the above.
            substring_array=Template.split(/([0-9a-f]{2,})|([0-9]+)/)
            substring_array.each_index {|i|
                next unless substring_array[i]=~/([0-9a-f]{2,})|([0-9]+)/
                saved_value=substring_array[i].clone
                if substring_array[i]=~/[0-9]{1,8}/
                    fuzzgen=base10_str_generator(substring_array[i])
                else
                    fuzzgen=hexstring_generator(substring_array[i])
                end
                while fuzzgen.next?
                    substring_array[i]=fuzzgen.next
                    fuzzed_string=substring_array.join
                    next if seen? fuzzed_string
		    puts substring_array[i-1..i+1].join
                    Fiber.yield fuzzed_string
                end
                substring_array[i]=saved_value
            }
            false
        end
        super
    end
end
