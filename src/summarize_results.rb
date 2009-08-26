path=ARGV[0]

def dump(results)
	results.sort.each {|k,v|
		puts "--- #{k} (count: #{v[0]}) ---"
		puts v[1]
	}
end

# get all detail files in the path
pattern=File.join(path, "detail*.txt")
results=Hash.new {|hsh, k| hsh[k]=[0,""]}

Dir.glob(pattern, File::FNM_DOTMATCH).each {|fn|
	contents=File.open(fn, "rb") {|ios| ios.read}
	if match=contents.match(/Hash=(.*)\)/)
		bucket=match[1]
		results[bucket][0]+=1
		crashfile=fn.sub('detail','crash').sub('.txt','-A.doc')
		if File.exists? crashfile
			file=crashfile
		end
		classification=contents.scan(/^CLASSIFICATION.*$/).join
		instructions=contents.scan(/^BASIC_BLOCK_INSTRUCTION:.*$/).join("\n")
		title=contents.scan(/^(BUG_TITLE.*) \(/).join
		results[bucket][1]=[title, instructions, classification, file].join("\n")
	end
}
dump results
