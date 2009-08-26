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
                    @bar.replace(" >> StructuredStorage")
                    raw_fib=raw[512,1472]
                    fib=WordStructures::WordFIB.new(raw_fib)
                    ole=Ole::Storage.open(f ,'rb')
                    ole.dir.entries('.')[2..-1].each {|dirname|
                        dircontents=ole.file.read(dirname) rescue ""
                        @link_window.append do
                            para link(dirname, :stroke=>chartreuse) {|x| 
                                @structure.replace( code hexdump(dircontents))
                                @baz.replace(" >> "+ dirname)
                             } 
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
