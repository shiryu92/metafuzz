require 'rubygems'
require 'json'
require 'binstruct'
require 'yaml'

class TraceTuple < Binstruct
    def self.pack_string; "NN"; end
    parse {|buf|
        unsigned buf, :from, 32, "From address"
        unsigned buf, :to, 32, "To address"
    }
end

class TraceLine < Binstruct

    TYPE_HASH={
        "CALL"=>0,
        "CALL INDIRECT"=>1,
        "RETURN"=>2
    }

    INT_HASH=TYPE_HASH.invert

    def self.type_to_int( arg )
        TYPE_HASH[arg]
    end

    def self.int_to_type( arg )
        INT_HASH[arg]
    end

    def self.pack_string; "cNNNNNNNNNNNN"; end

    parse {|buf|
        unsigned buf, :type, 8, "Entry type"
        unsigned buf, :from, 32, "From address"
        unsigned buf, :to, 32, "To address"
        unsigned buf, :eax, 32, "eax"
        unsigned buf, :ebx, 32, "ebx"
        unsigned buf, :ecx, 32, "ecx"
        unsigned buf, :edx, 32, "edx"
        unsigned buf, :esp, 32, "esp"
        unsigned buf, :ebp, 32, "ebp"
        unsigned buf, :esi, 32, "esi"
        unsigned buf, :edi, 32, "edi"
        unsigned buf, :flags, 32, "flags"
        unsigned buf, :hit_count, 32, "Hit count"
    }
end

TUPLE_COUNTER=Hash.new( 0 )

def postprocess( fname )
    begin
        fh=File.open(fname, "rb")
        begin
            tuple_handle=File.open(File.join(File.dirname(fname),File.basename(fname, ".txt")+".pp.tuples.txt"),"wb+")
            trace_line_handle=File.open(File.join(File.dirname(fname),File.basename(fname, ".txt")+".pp.full.txt"),"wb+")
            module_handle=File.open(File.join(File.dirname(fname),File.basename(fname, ".txt")+".pp.modules.yaml"),"wb+")
            module_hsh=Hash.new {|h,k| h[k]={}}
            until fh.eof?
                begin
                    raw_line=fh.readline
                    this_line=JSON.parse(raw_line)
                    if this_line["type"]=="module"
                        module_hsh[this_line["name"]]["start"]=this_line["base"]
                        module_hsh[this_line["name"]]["end"]=this_line["base"]+this_line["size"]
                        module_hsh[this_line["name"]]["checksum"]=this_line["checksum"]
                        module_handle.puts( YAML.dump( module_hsh ) )
                    else
                        # Write the simple tuple
                        this_tuple=[this_line["from"],this_line["to"]].pack(TraceTuple.pack_string)
                        TUPLE_COUNTER[this_tuple]+=1
                        # This is for recompression, so leave it human readable, one tuple per line.
                        tuple_handle.puts "#{this_line["from"]}:#{this_line["to"]}"
                        # Write the full tuple
                        # The records are packed without alignment, to be read with mmap()
                        unpacked=[]
                        unpacked << TraceLine.type_to_int( this_line["type"] )
                        unpacked << this_line["from"]
                        unpacked << this_line["to"]
                        unpacked << this_line["state"]["eax"]
                        unpacked << this_line["state"]["ebx"]
                        unpacked << this_line["state"]["ecx"]
                        unpacked << this_line["state"]["edx"]
                        unpacked << this_line["state"]["esp"]
                        unpacked << this_line["state"]["ebp"]
                        unpacked << this_line["state"]["esi"]
                        unpacked << this_line["state"]["edi"]
                        unpacked << this_line["state"]["flags"]
                        unpacked << TUPLE_COUNTER[this_tuple]
                        trace_line_handle.print( unpacked.pack( TraceLine.pack_string ) )
                    end
                rescue
                    $stderr.puts "Line didn't parse: #{$!}"
                    p raw_line
                    break
                end
            end
        rescue
            $stderr.puts "Couldn't open output file(s) for #{fname}: #{$!}, skipping"
            return
        ensure
            tuple_handle.close rescue nil
            trace_line_handle.close rescue nil
            module_handle.close rescue nil
        end
    rescue
        $stderr.puts "Couldn't open input file #{fname}: #{$!}, skipping"
        return
    ensure
        fh.close
    end
end

fnames=ARGV

fnames.each {|fname|
    postprocess( fname )
}

