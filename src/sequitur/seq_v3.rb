require 'rbsequitur'
require 'rubygems'
require "getopt/long"
include Getopt

opt = Long.getopts(
    ["--lines", "-l", BOOLEAN],
    ["--infile", "-i", REQUIRED],
    ["--help", "-h", OPTIONAL],
    ["--outfile", "-o", OPTIONAL]
)

usage=<<-DONE
Sequitur Compression in Ruby. Takes a file, compresses it using
the Sequitur algorithm (http://sequitur.info) and outputs a
YAML dump of the grammar, suitable for use in my sequitur
recompressor.

Command line options:
-h | --help     - This usage.
-i | --infile   - File to compress (required)
-o | --outfile  - Output, defaults to stdout
-l | --lines    - Tokenises input as one entry per line.
                  Defaults to string (one token per byte)
DONE

unless opt["i"] or opt["h"]
    print usage
    exit
else
    input=opt["i"]
    output=opt["o"] || $stdout
end
if opt["l"]
    read_method=:readline
else
    read_method=:getc
end

main_rule=Rule.new

File.open(input, "rb") {|ios|
    counter=0
    until ios.eof?
        # In ruby 1.8 "" << an_integer casts the int into
        # a character, so "" << an_int or a_string will work
        # either way
        sym=("" << ios.send(read_method))
        sym.chomp! if opt["l"]
        main_rule.last.insert_after( Terminal.new(sym) )
        main_rule.last.prev.check
        counter+=1
        if counter%1000==0
            print "\r#{counter}           #{main_rule.grammar.size}    #{sym.inspect}    " 
            $stdout.flush
        end
        if counter %1000000==0
            main_rule.grammar.each {|r| puts "#{r.number} ->  #{r.sequence}"}
        end
    end

    if output==$stdout
        main_rule.grammar.each {|r| p r.sequence}
    else
        File.open(output, "wb+") {|fh|
            main_rule.grammar.serialize( fh )
        }
    end
}
