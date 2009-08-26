require 'binstruct'
require 'wordstruct'
require 'ole/storage'
require 'diff/lcs'

begin
    orig_file=ARGV[0]
    corrupt_file=ARGV[1]
    raw_fib=IO.read(orig_file,1472,512)
    fib=WordStructures::WordFIB.new(raw_fib)
    ole_old=Ole::Storage.open(orig_file,'rb')
    table_stream_old=ole_old.file.read("1Table")
    ole_old.close
    ole_new=Ole::Storage.open(corrupt_file,'rb')
    table_stream_new=ole_new.file.read("1Table")
    #puts Diff::LCS.diff(table_stream_old,table_stream_new).to_s
    ole_new.close
    fc=:fcDggInfo
    lcb=:lcbDggInfo
    raw_old=table_stream_old[fib.send(fc),fib.send(lcb)]
    raw_new=table_stream_new[fib.send(fc),fib.send(lcb)]
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
                index=oldfield.match(/<IDX:(\d+)>/)[1].to_i
                puts "Before..."
                p oldbs.inspect[index-5..index-1]
                puts "Changed.."
                puts "--------"
                p oldfield
                p newfield
                puts "--------"
                puts "After..."
                p oldbs.inspect[index+1..index+5]
            end
        }
             
    }
rescue
    puts $!
end

