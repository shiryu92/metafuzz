require 'binstruct'


#data=File.open('c:\bunk\boof.doc',"rb") {|io| io.read(512)}
#a=WordStructures::StructuredStorageHeader.new(data)

raw=File.open('rawfib.txt',"r") {|io| io.readlines}
clumped=[[]]
raw.each {|line| 
	if line =~ /^Word \d+/ or line =~ /Introduced/
		clumped << []
	else
		clumped.last << line
	end
	clumped.pop if clumped.last[0] =~ /Microsoft Office/
}

final=[]	
clumped.each_index {|idx| 
	begin
	next if idx==0 or clumped[idx+1]==nil
	ary=clumped[idx]
	if ary[4] and ary[4] =~ /^:\d+$/
		type="bitfield_with_start"
	end
	if ary[0] =~ /^\d+$/  and not type
		type="bytes" 
	else
		type="bitfield" unless type
	end
	if type=="bitfield"
		#puts  "#{ary[0].chomp} : #{ary[2].chomp[1..-1]} : #{ary[4].chomp if ary[4]}"
		#final << [ary[0].chomp, ary[2].chomp[1..-1], ary[4].chomp if ary[4]]
		final << [ary[0].chomp, ary[2].chomp[1..-1],(ary[4].chomp rescue nil)]
	elsif type=="bitfield_with_start"
		#puts "#{ary[0].chomp} -- #{ary[2].chomp} : #{ary[4].chomp[1..-1]} : #{ary.last.chomp}"
		final << [ary[2].chomp,ary[4].chomp[1..-1],ary[0].chomp+' '+ary.last.chomp]
	else
		size=(clumped[idx+1][0].chomp.to_i - ary[0].chomp.to_i)*8
		p clumped[idx+1] if size<0
		#puts "#{ary[0].chomp} -- #{ary[2].chomp} : #{size} : #{ary[4].chomp if ary[4]}"
		final << [ary[2].chomp,size,(ary[0].chomp+' '+ary[4].chomp if ary[4])]
	end
	rescue 
		puts ary 
		puts type
		puts $!
		exit
	end
}

File.open("fib.txt","w+") {|io|
	io.puts "class WordFIB < Binstruct"
	io.puts
	final.each {|line| 
		next if line[1].to_i==0
		if line[2] && line[2].length > 64
			print "."
			line[2][63..-1]='[...]'
		end
		io.puts "\tunsigned :#{line[0]}, #{line[1]}, \"#{line[2]}\""
	}
        final.each_with_index {|line, i|
            if line[0]=~/^lcb/ and final[i-1][0]=~/^fc/
                io.puts "\tgroup :ol, :#{final[i-1][0]}, :#{line[0]}"
            end
        }
	io.puts
	io.puts "\tendianness \"intel\""
	io.puts "end"
}

	
