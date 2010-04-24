require 'rubygems'
require 'json'
require 'oklahoma_mixer'
require 'tracepp_lib'

TL_PACK_STRING=TracePP::TraceLine.pack_string

def postprocess( fname )
    begin
        fh=File.open(fname, "rb")
        begin
            db=OklahomaMixer.open(File.join(File.dirname(fname),File.basename(fname, ".txt")+".tch"), :mode=>'wct')
            trace_line_db=OklahomaMixer.open(
                File.join(File.dirname(fname),File.basename(fname, ".txt")+".tcf"),
                :width=>49,
                :limsiz=>1024*1024*1024,
                :mode=>'wct'
            ) # 1GB size limit, overwrite any existing DBs, 49 byte record size 
            tuple_handle=File.open(File.join(File.dirname(fname),File.basename(fname, ".txt")+".pp.tuples.txt"),"wb+")
            module_hsh=Hash.new {|h,k| h[k]={}}
            tuple_index=0
            tuple_counter=Hash.new( 0 )
            unpacked=[]
            until fh.eof?
                begin
                    raw_line=fh.readline
                    this_line=JSON.parse(raw_line)
                    if this_line["type"]=="module"
                        module_hsh["module:#{this_line["name"]}"]["start"]=this_line["base"]
                        module_hsh["module:#{this_line["name"]}"]["end"]=this_line["base"]+this_line["size"]
                        module_hsh["module:#{this_line["name"]}"]["checksum"]=this_line["checksum"]
                    else
                        this_tuple="#{this_line["from"]}->#{this_line["to"]}"
                        tuple_counter[this_tuple]+=1
                        unless key=db[this_tuple]
                            # Not seen before
                            # Write the tuple to the general DB, and also the inverse
                            key=tuple_index
                            db[key]=this_tuple
                            db[this_tuple]=key
                            tuple_index+=1
                        end
                        # This is for input into the recompression program
                        tuple_handle.puts "#{key}"
                        # Write the full trace line to the fixed length DB
                        unpacked.clear
                        unpacked << TracePP::TraceLine.type_to_int( this_line["type"] )
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
                        unpacked << tuple_counter[this_tuple]
                        packed=unpacked.pack( TL_PACK_STRING ) 
                        trace_line_db.store(:next, packed)
                    end
                rescue Exception => e  
                    puts e.message  
                    puts e.backtrace.inspect 
                    $stderr.puts "Line didn't parse: #{$!}"
                    p raw_line
                    break
                end
            end
            db.update module_hsh
            db["globals:module_count"]=module_hsh.size
            db["globals:trace_line_count"]=trace_line_db.size
            db["globals:unique_tuples"]=tuple_counter.size
        rescue
            $stderr.puts "Couldn't open output file(s) for #{fname}: #{$!}, skipping"
            return
        ensure
            db.close rescue nil
            trace_line_db.close rescue nil
            tuple_handle.close rescue nil
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

