require 'rubygems'
require 'thread'
require 'fuzzer'
require 'diff/lcs'
require 'wordstruct'
require 'ole/storage'
require 'mutations'
require 'tempfile'
require 'generators'


START_AT=0

Template=File.open( File.expand_path("~/wordcrashes/boof.doc"),"rb") {|io| io.read}
#Template=File.open( File.expand_path("~/wordcrashes/crash-192242.doc"),"rb") {|io| io.read}

def hexdump(str)
    ret=""
    str.unpack('H*').first.scan(/.{2}/).each_slice(16) {|s| 
        ret << "%-50s" % s.join(' ') 
        ret << s.map {|e| e.hex}.pack('c*').tr("\000-\037\177-\377",'.')
        ret << "\n"
    }
    ret
end

def dggdiff(old, new)

    begin
        puts "Diffing"
        orig_file=old
        corrupt_file=new
        raw_fib=IO.read(orig_file,1472,512)
        fib=WordStructures::WordFIB.new(raw_fib)
        ole_old=Ole::Storage.open(orig_file,'rb')
        table_stream_old=ole_old.file.read("1Table")
        ole_old.close
        ole_new=Ole::Storage.open(corrupt_file,'rb')
        table_stream_new=ole_new.file.read("1Table")
        ole_new.close
        fc=:fcDggInfo
        lcb=:lcbDggInfo
        raw_old=table_stream_old[fib.send(fc),fib.send(lcb)]
        raw_new=table_stream_new[fib.send(fc),fib.send(lcb)]
        puts "Same" if raw_old==raw_new
        dgg_parsed_old=[]
        while raw_old.length > 0
            dgg_parsed_old << WordStructures::WordDgg.new(raw_old)
            if raw_old.length > 0
                dgg_parsed_old << Binstruct.new(raw_old.slice!(0,1)) {|buf| unsigned buf, :foo, 8, "thing"}
            end
        end
        dgg_parsed_new=[]
        while raw_new.length > 0
            dgg_parsed_new << WordStructures::WordDgg.new(raw_new)
            if raw_new.length > 0
                dgg_parsed_new << Binstruct.new(raw_new.slice!(0,1)) {|buf| unsigned buf, :foo, 8, "thing"}
            end
        end
        dgg_parsed_old.zip(dgg_parsed_new) {|oldbs,newbs|
            oldbs.inspect.zip(newbs.inspect) {|oldfield,newfield|
                unless oldfield==newfield
                    #index=oldfield.match(/<IDX:(\d+)>/)[1].to_i
                    #puts "Before..."
                    #p oldbs.inspect[index-5..index-1]
                    #puts "Changed.."
                    p oldfield
                    p newfield
                    #puts "After..."
                    #p oldbs.inspect[index+1..index+5]
                end
            }

        }
    rescue
        puts $!
    end
end

unmodified_file=Template
header,raw_fib,rest=""
temp_file=Tempfile.new('wordfuzz')
File.open(temp_file.path,"wb+") {|io| io.write Template}
File.open(temp_file.path, "rb") {|io| 
    header=io.read(512)
    raw_fib=io.read(1472)
    rest=io.read
}
raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == unmodified_file
fib=WordStructures::WordFIB.new(raw_fib.clone)
raise RuntimeError, "Data Corruption - fib.to_s not raw_fib" unless fib.to_s == raw_fib
# Open the file, get a copy of the table stream
ole=Ole::Storage.open(temp_file.path,'rb')
# get the correct table stream 1Table or 0Table
table_stream=ole.file.read(fib.fWhichTblStm.to_s+"Table")
ole.close
fc=:fcDggInfo
lcb=:lcbDggInfo
#get the head, fuzztarget and rest from the table stream
puts "Inspecting #{fc.to_s}, #{lcb.to_s}, #{fib.send(lcb)}"
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
p dgg_parsed[2].inspect[290..-1]
dgg_parsed[2].flatten[299].set_value(0xf00c)
p dgg_parsed[2].inspect[290..-1]
new_ts=ts_head+dgg_parsed.join+ts_rest
puts Diff::LCS.diff(table_stream,new_ts).to_s
Ole::Storage.open(temp_file.path,'rb+') {|ole|
    ole.file.open(fib.fWhichTblStm.to_s+"Table","wb+") {|f| f.write( new_ts )}
}
File.open(File.expand_path("~/wordcrashes/manual.doc"),"wb+") {|fh| fh.write(File.read(temp_file.path))}
