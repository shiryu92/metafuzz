require 'rubygems'
require 'diff/lcs'
require 'streamdiff'
require 'getopt/long'
include Getopt

opt = Long.getopts(
    ["--old_file", "-o", REQUIRED],
    ["--new_file", "-n", REQUIRED],
    ["--help", "-h", OPTIONAL]
)

usage=<<-DONE
Diff two OLE2 files, ignoring the CompObj stream, which always changes
, and hexdump the differences by stream.

Command line options:
-h | --help     - This usage.
-o | --old_file - old file (template)
-n | --new_file - new file (crash)
DONE

unless (opt["o"] && opt["n"]) or opt["h"]
    print usage
    exit
end

begin
    old_ole=Ole::Storage.open(opt["o"])
    new_ole=Ole::Storage.open(opt["n"])
    old_streams=Hash[*(old_ole.dirents.map {|dirent| 
        next if dirent.dir?;[dirent.name,dirent.read]
    }).compact.flatten]
    new_streams=Hash[*(new_ole.dirents.map {|dirent| 
        next if dirent.dir?;[dirent.name,dirent.read]
    }).compact.flatten]
rescue
    raise RuntimeError, "Couldn't open files as OLE2: #{$!}"
ensure 
    old_ole.close
    new_ole.close
end

old={}
new={}

old_streams.each {|dirent,contents|
    # The compobj table changes virtually every time an OLE2 file is unpacked and repacked.
    # So don't check it for differences.
    next if dirent=~/compobj/i
    next if new_streams[dirent]==contents
    old[dirent],new[dirent]=StreamDiff::diff_and_markup(contents, new_streams[dirent])
}

old.each {|dirent, chunk_array|
    puts "Diffs in stream #{dirent}"
    new_diffs=new[dirent].reject {|chunk| chunk.chunk_type==:unchanged}
    old_diffs=chunk_array.reject {|chunk| chunk.chunk_type==:unchanged}
    zipped=old_diffs.zip( new_diffs )
    zipped.each {|pair|
        print "Old: +0x%-8x : " % [pair[0].offset]
        puts "#{StreamDiff::hexdump( pair[0].join )}"
        print "New: +0x%-8x : " % [pair[1].offset]
        puts "#{StreamDiff::hexdump( pair[1].join )}"
    }
}
