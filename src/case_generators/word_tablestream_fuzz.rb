require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'thread'
require 'fuzzer'
require 'fib'
require 'diff/lcs'
require 'wordstruct'
require 'ole/storage'
require 'mutations'

module Producer

    def each_item
        begin
            unmodified_file=File.open( 'c:\bunk\foo.doc',"rb") {|io| io.read}
            header,raw_fib,rest=""
            prod_queue.template=unmodified_file
            unmodified_io=StrinIO.new(unmodified_file.clone)
            header=unmodified_io.read(512)
            raw_fib=unmodified_io.read(1472)
            rest=unmodified_io.read
            raise RuntimeError, "Producer: Data Corruption" unless header+raw_fib+rest == unmodified_file
            fib=WordStructures::WordFIB.new(raw_fib)
            # Open the file, get a copy of the table stream
            unmodified_io.rewind
            table_stream=""
            Ole::Storage.open(unmodified_io) {|ole|
                table_stream=ole.file.read(fib.fWhichTblStm.to_s+"Table")
            }
            fib.groups[:ol].each {|fc,lcb|
                gJunk=Mutations.create_string_generator(Array((0..255)).map {|e| "" << e},50000)
                while gJunk.next?
                    # Append random junk to the end of the stream
                    fuzzed_table=table_stream + gJunk.next
                    # open the new file and insert the modified table stream
                    Ole::Storage.open('c:\bunk\tmp.doc','rb+') {|ole|
                        ole.file.open("1Table","wb+") {|f| f.write( fuzzed_table )}
                    }
                    # Read in the new file contents
                    File.open( 'c:\bunk\tmp.doc',"rb") {|io| 
                        header=io.read(512)
                        raw_fib=io.read(1472)
                        rest=io.read
                    }
                    newfib=WordStructures::WordFIB.new(raw_fib)
                    # point the fc to the start of the junk
                    newfib.send((fc.to_s+'=').to_sym, table_stream.length)
                    # set the lcb to the size of the junk
                    newfib.send((lcb.to_s+'=').to_sym, fuzzed_table.length-table_stream.length)
                    # and add it to the queue.
                    yield (header+newfib.to_s+rest)
                end
            }
        end
    end

    module_function :each_item

end
