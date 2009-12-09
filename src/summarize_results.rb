require 'fileutils'
SOURCE_PATH=ARGV[0]
DEST_PATH=ARGV[1] || ""

def dump(results)
	results.sort.each {|k,v|
		puts "--- #{k} (count: #{v[0]}) ---"
		puts v[1].join("\n")
	}
end

def sample(results)
    return if DEST_PATH.empty?
    FileUtils.mkdir(DEST_PATH) unless File.directory? DEST_PATH
    puts "Copying to : #{DEST_PATH}"
    results.each {|k,v|
	    next unless v[1][3]
	    puts "File: #{v[1][3]}"
        FileUtils.cp(v[1][3],DEST_PATH)
    }
end

# get all detail files in the SOURCE_PATH
pattern=File.join(SOURCE_PATH, "detail*.txt")
results=Hash.new {|hsh, k| hsh[k]=[0,""]}

Dir.glob(pattern, File::FNM_DOTMATCH).each {|fn|
	contents=File.open(fn, "rb") {|ios| ios.read}
	if match=contents.match(/Hash=(.*)\)/)
		bucket=match[1]
		results[bucket][0]+=1
		crashfile1=fn.sub('detail','crash').sub('.txt','-A.doc')
		crashfile2=fn.sub('detail','crash').sub('.txt','.doc')
		if File.exists? crashfile1
			file=crashfile1
		elsif File.exists? crashfile2
			file=crashfile2
		end
		classification=contents.scan(/^CLASSIFICATION.*$/).join
		instructions=contents.scan(/^BASIC_BLOCK_INSTRUCTION:.*$/).join("\n")
		title=contents.scan(/^(BUG_TITLE.*) \(/).join
		results[bucket][1]=[title, instructions, classification, file]
	end
}
dump results
sample results
