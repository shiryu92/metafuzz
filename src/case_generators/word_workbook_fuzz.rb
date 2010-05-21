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

    def hexdump(str)
        ret=""
        str.unpack('H*').first.scan(/.{2}/).each_slice(16) {|s| 
            ret << "%-50s" % s.join(' ') 
            ret << s.map {|e| e.hex}.pack('c*').tr("\000-\037\177-\377",'.')
            ret << "\n"
        }
        ret
    end

    def initialize
        @block=Fiber.new do
            begin
                header,raw_fib,rest=""
                unmodified_io=StringIO.new(Template)
                header=unmodified_io.read(512)
                raw_fib=unmodified_io.read(1472)
                rest=unmodified_io.read
                raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == Template
                fib=WordStructures::WordFIB.new(raw_fib.clone)
                raise RuntimeError, "Data Corruption - fib.to_s not raw_fib" unless fib.to_s == raw_fib
                workbook_stream=""
                Ole::Storage.open(unmodified_io) {|ole
                    workbook_stream=ole.dirents.find {|de| de.name=="Workbook"}.read
                }
                # run a couple of RollingCorruptors over the whole lot
                # get the weird code bit
                # chop into 16 bits
                # shuffle the bits, join and write
                # define a character list taken from the code bit
                # using the list, replace a bit, join and write
                # using the list, insert a bit, join and write
                # replace a bit with format string characters
                # insert loads of text into [Red]
                # mess with the pascal strings (wishful thinking)
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
