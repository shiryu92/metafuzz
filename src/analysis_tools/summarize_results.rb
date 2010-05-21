require 'fileutils'
require 'trollop'

OPTS = Trollop::options do 
    opt :source_dir, "Source Dir", :type => :string
    opt :dest_dir, "Dest Dir (Optional)", :type => :string
    opt :template, "Template File (Optional)", :type => :string
    version "summarize_results.rb 0.3 (c) Ben Nagy, 2010"
    banner <<-EOS

Usage:
Summarizes the results for a directory full of crashes, where each crash file is
accompanied by a detail<crash_name>.txt file - outputs data for the first file it
finds from each !exploitable bucket. Optionally, copies one file from each bucket
to dest-dir. Optionally, if given a template file, adds the output from ole2diff 
(stream by stream diff for OLE2 files) into the summary.

    ruby summarize_results.rb --source-dir /foo --dest-dir /bar --template foo.doc
EOS
end

SOURCE_PATH=OPTS[:source_dir]
DEST_PATH=OPTS[:dest_dir]

def dump(results)
    results.sort.each {|k,v|
        puts "--- #{k} (count: #{v[0]}) ---"
        puts v[1].join("\n")
        if opts[:template_given]
            next unless v[1][3]
            puts `ruby ole2diff.rb -o #{opts[:template]} #{v[1][3]}`
        end
    }
end

def sample(results)
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
sample results if opts[:dest_dir_given]
