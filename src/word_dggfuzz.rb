require 'rubygems'
require 'fuzzer'
require 'wordstruct'
require 'ole/storage'

class Producer < Generators::NewGen

    START_AT=0

    Template=File.open( File.expand_path("~/fuzzserver/boof.doc"),"rb") {|io| io.read}

    def seen?( str )
        hsh=Digest::MD5.hexdigest(str)
        seen=@duplicate_check[hsh]
        @duplicate_check[hsh]=true
        @duplicate_check.shift if @duplicate_check.size > SEEN_LIMIT
        seen
    end

    def initialize
        @duplicate_check=Hash.new(false)
        @block=Fiber.new do
            begin
                unmodified_file=StringIO.new(Template.clone)
                header=unmodified_file.read(512)
                raw_fib=unmodified_file.read(1472)
                rest=unmodified_file.read
                raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == Template
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
                dgg_parsed.each {|bs|
                    typefixer=proc {|bs| bs.flatten.each {|f|
                            if f.name==:recType
                                f.set_value(f.get_value | 0xf000)
                            end
                        }
                        bs
                    }
                    f=Fuzzer.new(bs,typefixer)
                    f.preserve_length=true
                    f.verbose=false
                    #p f.count_tests(1024,false)
                    f.basic_tests(1024,false, START_AT) {|fuzz|
                        #head+fuzzed+rest
                        ts_gunk=dgg_parsed.map {|obj| obj==bs ? fuzz : obj}.join
                        #raise RuntimeError, "DggFuzz: Dgg length mismatch" unless ts_gunk.length==1814
                        fuzzed_table=ts_head+ts_gunk+ts_rest
                        raise RuntimeError, "Dggfuzz: fuzzed table stream same as old one!" if fuzzed_table==table_stream
                        next if seen? fuzzed_table
                        #write the modified stream into the temp file
                        unmodified_file.rewind
                        Ole::Storage.open(unmodified_file) {|ole|
                            # get the correct table stream 1Table or 0Table
                            ts=ole.dirents.map{|d| d.name}.select {|s| s=~/table/i}[0][0]
                            ole.file.open(ts+"Table","wb+") {|f| f.write( fuzzed_table )}
                        }
                        unless (ts_gunk.length-fuzztarget.length) == 0
                            raise RuntimeError, "Dggfuzz: Fuzzer is set to preserve length, but delta !=0?"
                        end
                        #add to the queue
                        unmodified_file.rewind
                        Fiber.yield( unmodified_file.read )
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
