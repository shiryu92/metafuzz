require 'rubygems'
require File.dirname(__FILE__) + '/../core/fuzzer_new'
require File.dirname(__FILE__) + '/wordstruct'
require 'thread'
require 'ole/storage'
require 'zlib'

class Producer < Generators::NewGen

    START_AT=0
    SEEN_LIMIT=1024


    def seen?( str )
        hsh=Digest::MD5.hexdigest(str)
        #hsh=Zlib.crc32(str)
        seen=@duplicate_check[hsh]
        @duplicate_check[hsh]=true
        @duplicate_check.shift if @duplicate_check.size > SEEN_LIMIT
        seen
    end

    def initialize( template_fname )
        @template=File.open( template_fname ,"rb") {|io| io.read}
        @duplicate_check=Hash.new(false)
        @block=Fiber.new do
            begin
                unmodified_file=StringIO.new(@template.clone)
                header=unmodified_file.read(512)
                raw_fib=unmodified_file.read(1472)
                rest=unmodified_file.read
                raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == @template
                fib=WordStructures::WordFIB.new(raw_fib.clone)
                raise RuntimeError, "Data Corruption - fib.to_s not raw_fib" unless fib.to_s == raw_fib
                # Open the file, get a copy of the table stream
                unmodified_file.rewind
                ole=Ole::Storage.open(unmodified_file)
                # get the correct table stream 1Table or 0Table
                table_stream=ole.file.read(fib.fWhichTblStm.to_s+"Table")
                ole.close
                fc=:fcDggInfo
                lcb=:lcbDggInfo
                #get the head, fuzztarget and rest from the table stream
                puts "Starting #{fc.to_s}, #{lcb.to_s}, #{fib.send(lcb)}"
                ts_head=table_stream[0,fib.send(fc)]
                fuzztarget=table_stream[fib.send(fc),fib.send(lcb)]
                ts_rest=table_stream[fib.send(fc)+fib.send(lcb)..-1]
                raise RuntimeError, "Data Corruption - TS corrupt" unless (ts_head+fuzztarget+ts_rest)==table_stream
                raise RuntimeError, "Data Corruption - LCB / fuzztarget length mismatch" unless fib.send(lcb)==fuzztarget.length
                begin
                    dgg_parsed=[]
                    fuzzcopy=fuzztarget.clone
                    while fuzzcopy.length > 0
                        dgg_parsed << WordStructures::WordDgg.new(fuzzcopy)
                        if fuzzcopy.length > 0
                            dgg_parsed << Binstruct.new(fuzzcopy.slice!(0,1)) {|buf| unsigned buf, :foo, 8, "thing"}
                        end
                    end
                rescue
                    raise RuntimeError, "DggFuzz: #{$!}"
                end
                raise RuntimeError, "Data Corruption - Binstruct.to_s not fuzztarget" unless dgg_parsed.map {|s| s.to_s}.join == fuzztarget
                typefixer=proc {|bs| 
                    bs.deep_each {|f|
                        if f.name==:recType
                            f.set_value(f.get_value | 0xf000)
                        end
                    }
                    bs
                }
                dgg_parsed.each_index {|i|
                    if i==0
                        before=""
                    else
                        before=dgg_parsed[0..i-1].join
                    end
                    bs=dgg_parsed[i]
                    after=dgg_parsed[i+1..-1].join
                    f=Fuzzer.new(bs,typefixer)
                    f.preserve_length=true
                    f.verbose=false
                    #p f.count_tests(1024,false)
                    f.basic_tests(1024,false, START_AT,2) {|fuzz|
                        # The fuzzed item has been directly modified inside the 
                        # dgg_parsed array.
                        fuzzstring=fuzz.to_s
                        next if seen? fuzzstring
                        fuzzed_table=("" << ts_head << before << fuzzstring << after << ts_rest)
                        #write the modified stream into the temp file
                        unmodified_file.rewind
                        Ole::Storage.open(unmodified_file) {|ole|
                            # get the correct table stream 1Table or 0Table
                            ole.file.open(fib.fWhichTblStm.to_s+"Table","wb+") {|f| f.write( fuzzed_table )}
                        }
                        unless (fuzzed_table.length-table_stream.length) == 0
                            raise RuntimeError, "Dggfuzz: Fuzzer is set to preserve length, but delta !=0?"
                        end
                        #add to the queue
                        unmodified_file.rewind
                        Fiber.yield( unmodified_file.read )
                    }
                }
            rescue Exception => e
                puts "Production failed: #{$!}";$stdout.flush
                puts e.backtrace
                exit
            end
            false
        end
        super
    end
end
