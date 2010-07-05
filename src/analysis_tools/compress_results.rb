require 'fileutils'
path=ARGV[0]

# get all detail files in the path
pattern=File.join(path, "*.txt")
results=Hash.new {|hsh, k| hsh[k]=[0,[]]}
deleted_crashes=0
deleted_results=0

Dir.glob(pattern, File::FNM_DOTMATCH).tap {|a| puts "#{a.length} detail files total"}.each {|fn|
	contents=File.open(fn, "rb") {|ios| ios.read}
	if match=contents.match(/Hash=(.*)\)/)
		bucket=match[1]
		results[bucket][0]+=1
		if results[bucket][0] >= 1024
			FileUtils.rm_f(fn)
			deleted_results+=1
		end
		crashfile=fn.sub('.txt','.raw')
		if File.exists? crashfile
			if results[bucket][1].size < 1024
				results[bucket][1]<<crashfile
			else
				FileUtils.rm_f(crashfile)
				deleted_crashes+=1
			end
		end
	end
}
puts "Deleted #{deleted_results} detail files and #{deleted_crashes} crash files."
