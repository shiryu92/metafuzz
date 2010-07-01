require 'rubygems'
require File.dirname(__FILE__) + '/../core/fuzzer_new'
require File.dirname(__FILE__) + '/wordstruct'
require 'thread'
require 'ole/storage'

# This is a fully working case generator. It mutates a template file by reading the FIB
# and then looping through all the offset/length pairs (defined in the structure). Each
# linked structure is read from the Table stream and then fed into a very simple string 
# fuzzer. Then we adjust the offset/length stuff in the FIB if the length changed, pack
# the file back up and send it.
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class Producer < Generators::NewGen

    def initialize( template_fname )
        @template=File.open( template_fname ,"rb") {|io| io.read}
        @block=Fiber.new do
            begin
                io=StringIO.new(@template.clone)
                @template.freeze
                header, raw_fib, rest=io.read(512), io.read(1472), io.read
                fib=WordStructures::WordFIB.new(raw_fib)
                # Open the file, get a copy of the table stream
                io.rewind
                ole=Ole::Storage.open(io)
                table_stream=ole.file.read(fib.fWhichTblStm.to_s+"Table")
                ole.close
                fib.groups[:ol].shuffle.each {|fc,lcb|
                    next if fib.send(lcb)==0
                    #get the head, fuzztarget and rest from the table stream
                    puts "Starting #{fc.to_s}, #{lcb.to_s}, #{fib.send(lcb)}"
                    ts_head=table_stream[0,fib.send(fc)]
                    fuzztarget=table_stream[fib.send(fc),fib.send(lcb)]
                    ts_rest=table_stream[fib.send(fc)+fib.send(lcb)..-1]
                    raise RuntimeError, "Data Corruption" unless (ts_head+fuzztarget+ts_rest)==table_stream
                    raise RuntimeError, "Data Corruption" unless fib.send(lcb)==fuzztarget.length
                    #create a new Fuzzer using the fuzztarget
                    bs=Fuzzer.string_to_binstruct(fuzztarget,32,:little)
                    raise RuntimeError, "Data Corruption" unless bs.to_s == fuzztarget
                    f=Fuzzer.new(bs)
                    f.verbose=false
                    #puts "Expecting #{f.count_tests(10000,false)} tests..."
                    f.basic_tests(10000,false,0,2) {|fuzz|
                        fuzzstring=fuzz.to_s
                        #head+fuzzed+rest
                        fuzzed_table=ts_head+fuzzstring+ts_rest
                        #write the modified stream
                        io.rewind
                        Ole::Storage.open(io) {|ole|
                            ole.file.open(fib.fWhichTblStm.to_s+"Table","wb+") {|f| f.write( fuzzed_table )}
                        }
                        io.rewind
                        delta=fuzzstring.length-fuzztarget.length
                        unless delta == 0
                            # Read in the new file contents
                            header, raw_fib, rest=io.read(512), io.read(1472), io.read
                            newfib=WordStructures::WordFIB.new(raw_fib)
                            #adjust the byte count for this structure
                            newfib.send((lcb.to_s+'=').to_sym, fuzzstring.length)
                            #adjust the offsets for all subsequent structures
                            fib.groups[:ol].each {|off,len|
                                if (fib.send(off) > fib.send(fc)) and fib.send(len) > 0
                                    newfib.send((off.to_s+'=').to_sym, fib.send(off)+delta)
                                end
                            }
                            Fiber.yield( (header+newfib.to_s+rest) )
                        else
                            Fiber.yield io.read
                        end
                    }
                }
            rescue
                puts "Production failed: #{$!}";$stdout.flush
                exit
            end
            false
        end
        super
    end
end
