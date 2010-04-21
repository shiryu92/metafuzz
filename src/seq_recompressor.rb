# Prototype code to "recompress" sequences with a saved Sequitur grammar
# (c) Ben Nagy, 2010
require File.dirname(__FILE__) + '/seq_dump_api'
require 'rubygems'
require "getopt/long"
require 'yaml'
include Getopt

class RecompressorNode
    attr_accessor :token, :exits, :terminal

    def initialize( token )
        @exits||={}
        @token=token
        @terminal=false
    end

    def is_terminal?
        !!(terminal)
    end

    def traverse( token, build=false )
        if exits[token]
            exits[token]
        elsif build
            exits[token]=RecompressorNode.new( token )
        else
            false
        end
    end

    def inspect
        "node"
        #"T:#{token} #{exits.keys.inspect}#{self.is_terminal?? "!(#{@terminal})" : ''}"
    end
end

opt = Long.getopts(
    ["--lines", "-l", BOOLEAN],
    ["--infile", "-i", REQUIRED],
    ["--grammar", "-g", REQUIRED],
    ["--help", "-h", OPTIONAL]
)

usage=<<-DONE
Sequitur Re-Compression in Ruby. Given a saved grammar
from the Sequitur example code, reads the grammar file 
and a file to compress and compresses the file with 
the saved grammar.

Command line options:
-h | --help     - This usage.
-i | --infile   - File(s) to compress (required)
                - use more than once for multiple files
-g | --grammar  - Saved grammar file (required)
-l | --lines    - Tokenises input as one entry per line.
                  Defaults to string (one token per byte)
DONE

unless opt["i"] && opt["g"] or opt["h"]
    print usage
    exit
else
    input=opt["i"]
    begin
        seq_dump=SequiturDump.new( opt["g"], (opt["l"]? :lines : :characters) )
        puts "Using the following saved grammar"
        puts "---------"
        for idx in 0..seq_dump.grammar.size-1
            puts "#{idx} -> #{seq_dump.grammar[idx].inspect}"
        end
        puts "---------\n"
    rescue
        puts "Unable to parse grammar file #{opt["g"]} - #{$!}"
    end

    output=opt["o"] || $stdout
end
if opt["l"]
    read_method=:readline
else
    read_method=:getc
end

# Build the FSA from the saved grammar
puts "Building FSA now."
graph_head=RecompressorNode.new( nil )
for idx in 1..seq_dump.grammar.size-1
    active_node=graph_head
    seq_dump.expand_rule( idx ).each {|token|
        active_node=active_node.traverse(token, build=true)
    }
    active_node.terminal=idx
end

puts "FSA built"

# OK, so this doesn't work. Guess I need to find a serialisation method
# that doesn't blow up the stack.
#out=File.open("testfsa.yaml","wb+") {|io| io.write YAML.dump(graph_head) }

class Stream < Array
    def initialize( fh, &read_block)
        @fh=fh
        @read_block=read_block
    end

    def next_token
        begin
            @fh.instance_eval( &@read_block )
        rescue
            nil
        end
    end

    def shift
        return next_token if self.empty?
        super
    end
end

if opt["l"]
    read_blk=proc do |fh| fh.readline.chomp end
else
    read_blk=proc do |fh| fh.getc.chr end
end

def recompress( unprocessed, graph_head, grammar )
    active_node=graph_head
    checkpoint=false
    buffer=[]
    emitted=[]
    while token=unprocessed.shift
        # The order of data is
        # emitted <- buffer <- token <- unprocessed
        if new_node=active_node.traverse( token )
            # This transition is in the state machine.
            # 1. Move to the next node
            # 2. add the token to the buffer
            active_node=new_node
            # 3. If this token is the last token in a complete rule,
            #    save a checkpoint. If the match continues, the 
            #    checkpoint will be overwritten with the longest
            #    match so far.
            if active_node.is_terminal?
                checkpoint=active_node.terminal
                buffer=[]
            else
                buffer << token
            end
        else
            # We couldn't match this token at the start of the FSA
            # so just emit it.
            if active_node==graph_head
                emitted.push token
            else
                # We couldn't match this token somewhere inside the state
                # machine.
                if checkpoint
                    # Emit the saved checkpoint
                    emitted.push checkpoint
                    checkpoint=false
                else
                    # Emit the first character of the buffer
                    emitted.push buffer.shift
                end
                # In either case, put everything else back into the
                # unprocessed stream and reset the machine.
                unprocessed.unshift token
                unprocessed.unshift *buffer
                active_node=graph_head
                buffer=[]
            end
        end
    end
    emitted.push *checkpoint if checkpoint
    [emitted, buffer]
end

opt["infile"].each {|filename|
    emitted, residue=recompress( Stream.new( File.open(filename, "rb"), &read_blk), graph_head, seq_dump )
    # There are a few cases where the buffer in the recompress method
    # still holds data that can be compressed, so we have to recurse 
    # on the residue.
    until residue.empty?
        extra, residue=recompress( residue, graph_head, seq_dump )
        emitted.push *extra
        emitted.push residue.shift unless residue.empty?
    end

    puts "S  -> #{emitted.inspect}"
    puts "Recompressed: #{emitted.length} tokens, Original: #{seq_dump[0].length} tokens."
    File.open( "recompressed-#{filename}", "wb+" ) {|io|
        emitted.each {|token| 
            if token.is_a? String
                io.puts "&#{token}"
            else
                io.puts token
            end
        }
    }
}
