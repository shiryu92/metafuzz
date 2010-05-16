Shoes.setup do
    gem 'ruby-ole'
end
require 'fib'
require 'binstruct'
require 'wordstruct'
require 'ole/storage'
require 'enumerator'


Shoes.app do

    def hexdump(str)
        ret=""
        str.unpack('H*').first.scan(/.{2}/).each_slice(16) {|s| 
            ret << "%-50s" % s.join(' ') 
            ret << s.map {|e| e.hex}.pack('c*').tr("\000-\037\177-\377",'.')
            ret << "\n"
        }
        ret
    end

    background black

    flow do
        stack :width => "100%" do
            flow do
                button("Select File") do
                    f=ask_open_file
                    raw=File.open( f ,"rb") {|io| 
                        io.read
                    }
                    @foo.replace(" "+f)
                    @bar.replace(" >> FIB")
                    raw_fib=raw[512,1472]
                    fib=WordStructures::WordFIB.new(raw_fib)
                    ole=Ole::Storage.open(f ,'rb')
                    table_stream=ole.file.read("1Table")
                    fib.groups[:ol].each {|fc, lcb|
                        s="#{fc.to_s}"
                        @link_window.append do
                            para( link(s, :stroke=>chartreuse) {|x| 
                                            @structure.replace( code hexdump(table_stream[fib.send(fc),fib.send(lcb)]))
                                            @baz.replace(" >> "+fc.to_s)
                                         }, 
                                 " ", 
                                 fib.send(lcb).to_s, :stroke => chartreuse, :size => 10) 
                        end
                    }
                end
                @foo=para "", :stroke=>chartreuse, :margin_left=>30
                @bar=para "", :stroke=>chartreuse, :margin_left=>30
                @baz=para "", :stroke=>chartreuse, :margin_left=>30
            end
        end
        @link_window=stack :width => "200px", :margin => 10
        stack :width => "-200px", :margin => 10 do
            @structure=para " ", :stroke => chartreuse
        end
    end


end
