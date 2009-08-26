require 'rubygems'
require 'thread'
require 'fuzzer'
require 'diff/lcs'
require 'wordstruct'
require 'ole/storage'
require 'mutations'
require 'tempfile'
require 'generators'

class Producer < Generators::NewGen

    START_AT=0

    #Template=File.open( File.join(Config["WORK DIR"],"boof.doc"),"rb") {|io| io.read}
    Template=File.open( File.expand_path("~/wordcrashes/boof.doc"),"rb") {|io| io.read}
    ValidSprms=[]
    File.open("sprms_sorted.txt","rb") {|io|
        io.each_line {|l| ValidSprms << l.split(/\W+/)[1].to_i(16)}
    }
    #Template=File.open( File.expand_path("~/wordcrashes/crash-192242.doc"),"rb") {|io| io.read}

    def seen?( str )
        hsh=Digest::MD5.hexdigest(str)
        seen=@duplicate_check[hsh]
        @duplicate_check[hsh]=true
        @duplicate_check.shift if @duplicate_check.size > SEEN_LIMIT
        seen
    end

    def hexdump(str)
        ret=""
        str.unpack('H*').first.scan(/.{2}/).each_slice(16) {|s| 
            ret << "%-50s" % s.join(' ') 
            ret << s.map {|e| e.hex}.pack('c*').tr("\000-\037\177-\377",'.')
            ret << "\n"
        }
        ret
    end

    def parse_as_sprms( buffer )
        raw=buffer.dup
        parsed=[]
        while raw.length > 0
            sprm=WordStructures::WordSPRM.new(raw)
            return nil unless sprm.length_check==sprm[:operand].to_s.length
            return nil unless ValidSprms.find {|s| sprm.to_s[0..1].unpack('v').first==s}
            parsed << sprm
        end
        return nil unless parsed.join.length==buffer.length
        return nil if parsed.length < 2
        parsed
    end

    def initialize
        @duplicate_check=Hash.new(false)
        @block=Fiber.new do
            begin
                header,raw_fib,rest=""
                unmodified_io=StringIO.new(Template.clone)
                header=unmodified_io.read(512)
                raw_fib=unmodified_io.read(1472)
                rest=unmodified_io.read
                raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == Template
                fib=WordStructures::WordFIB.new(raw_fib.clone)
                raise RuntimeError, "Data Corruption - fib.to_s not raw_fib" unless fib.to_s == raw_fib
                word_stream=""
                Ole::Storage.open(unmodified_io) {|ole|
                    word_stream=ole.dirents.find {|de| de.name=="WordDocument"}.read
                }
                word_stream.freeze 
                # OK, this is a slow and crappy way to do this, but I couldn't work out how to parse
                # all the structures that might contain grpprls (groups of SPRMs)
                while (idx||=0) < word_stream.length
                    len=word_stream[idx].ord
                    # parse forward len bytes as a possible array of sprms
                    sprm_ary=parse_as_sprms(word_stream.slice(idx+1,len))
                    if sprm_ary #that worked, add the idx and the array to the hash
                        (grpprl_hash||={})[idx]=sprm_ary
                        # skip ahead len bytes.
                        idx+=len+1
                        break
                    else # it didn't parse, keep on truckin'
                        idx+=1
                    end
                end
                sprms=grpprl_hash.keys.sort
                next_sprm=sprms.shift
                chunked=[]
                idx=next_sprm
                chunked << word_stream[0..idx-1]
                while idx < word_stream.length
                    chunked << word_stream[idx..next_sprm-1] unless idx==next_sprm
                    break if next_sprm >= word_stream.length
                    chunked << word_stream[next_sprm]+(grpprl_hash[next_sprm].join)
                    idx=next_sprm+(word_stream[next_sprm].ord)+1
                    next_sprm=(sprms.shift || word_stream.length+1)
                end
                raise RuntimeError, "Prod: Length mismatch for shuffle" unless chunked.join.length==word_stream.length
                puts "starting permute"
                1000.times do
                    chunked=chunked.sort_by {rand}
                    final=StringIO.new(Template.clone)
                    Ole::Storage.open(final) {|ole|
                        ole.file.open("WordDocument","wb+") {|io| io.write chunked.join}
                    }
                    final.rewind
                    final=final.read
                    raise RuntimeError, "Production: no changes!" if final==Template
                    Fiber.yield final
                end  
                grpprl_hash.each {|len_idx,sprm_ary|
                    lenstruct=Binstruct.new(word_stream.clone[len_idx].chr) {|buf| unsigned buf, :thing, 8, "len"}
                    f=Fuzzer.new(lenstruct)
                    f.preserve_length=true
                    f.basic_tests {|bs|
                        fuzzed_stream=word_stream[0..len_idx-1]+bs.to_s+word_stream[len_idx+1..-1]
                        next if seen? fuzzed_stream
                        final=StringIO.new(Template.clone)
                        Ole::Storage.open(final) {|ole|
                            ole.file.open("WordDocument","wb+") {|io| io.write fuzzed_stream}
                        }
                        final.rewind
                        final=final.read
                        raise RuntimeError, "Production: no changes!" if final==Template
                        Fiber.yield final
                    }
                    p sprm_ary
                    sprm_ary.each {|sprm|
                        f=Fuzzer.new(sprm)
                        f.basic_tests(1024,false) {|fuzzed_sprm|
                            fuzzed=sprm_ary.map {|elem| elem==sprm ? fuzzed_sprm : elem}.join
                            fuzzed_stream=word_stream[0..len_idx]+fuzzed+word_stream[len_idx+fuzzed.length+1..-1]
                            next if seen? fuzzed_stream
                            final=StringIO.new(Template.clone)
                            Ole::Storage.open(final) {|ole|
                                ole.file.open("WordDocument","wb+") {|io| io.write fuzzed_stream}
                            }
                            final.rewind
                            final=final.read
                            raise RuntimeError, "Production: no changes!" if final==Template
                            Fiber.yield final
                        }
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

if $0==__FILE__
    p=Producer.new
end
