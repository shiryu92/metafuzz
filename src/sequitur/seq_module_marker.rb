# Some test code to mark up modules in diffed, sequitur compressed
# output.
# (c) Ben Nagy, 2010

require File.dirname(__FILE__) + '/seq_dump_api'
require 'rubygems'
require "getopt/long"
require 'json'
require 'yaml'
include Getopt

opt = Long.getopts(
    ["--old_dump", "-o", REQUIRED],
    ["--new_dump", "-n", REQUIRED],
    ["--diff", "-d", REQUIRED],
    ["--grammar", "-g", REQUIRED],
    ["--compress", "-c", OPTIONAL],
    ["--help", "-h", OPTIONAL]
)

usage=<<-DONE
Once two traces are sequitur-recompressed, take the
sdiff output and replace node symbols with module and
output.

Command line options:
-h | --help     - This usage.
-o | --old_dump - trace dump from old file (template)
-n | --new_dump - trace dump from new file (crash)
-d | --diff     - sdiff -d output of recompressed node sequences
-g | --grammar  - sequitur output file, containing the grammar
-c | --compress - compressed output for identical lines
DONE

unless (opt["o"] && opt["n"] && opt["d"] && opt["g"]) or opt["h"]
    print usage
    exit
end

if File.exists? "#{opt["o"]}.yaml"
    old_modules=YAML.load(File.read("#{opt["o"]}.yaml"))
else
    old_modules=Hash.new {|h,k| h[k]={}}
    File.open(opt["o"], "rb") {|ios|
        ios.each_line {|line|
            # This saves calling JSON.parse on lines that aren't
            # module loads, although it's a bit ugly.
            next unless line[9].chr=='m'
            parsed=JSON.parse(line)
            old_modules[parsed["name"]]["start"]=parsed["base"]
            old_modules[parsed["name"]]["end"]=parsed["base"]+parsed["size"]
        }
    }
    File.open("#{opt["o"]}.yaml","wb+") {|io| io.puts YAML.dump(old_modules)}
end

if File.exists? "#{opt["n"]}.yaml"
    new_modules=YAML.load(File.read("#{opt["n"]}.yaml"))
else
    new_modules=Hash.new {|h,k| h[k]={}}
    File.open(opt["n"], "rb") {|ios|
        ios.each_line {|line|
            # This saves calling JSON.parse on lines that aren't
            # module loads, although it's a bit ugly.
            next unless line[9].chr=='m'
            parsed=JSON.parse(line)
            new_modules[parsed["name"]]["start"]=parsed["base"]
            new_modules[parsed["name"]]["end"]=parsed["base"]+parsed["size"]
        }
    }
    File.open("#{opt["n"]}.yaml","wb+") {|io| io.puts YAML.dump(new_modules)}
end

class Emitter

    def initialize( seq_dump, old_modules, new_modules, compress=false )
        @seq_dump=seq_dump
        @compress=compress
        @old_modules=old_modules
        @new_modules=new_modules
        @rule_length_cache||={}
        @buffer=[]
        @skipped_lines=0
        @skipped_nodes=0
    end
    def handle_line( line )
        line=line.split
        if line[0]==">"
            # only in new file
            clear_unchanged_buffer
            new_str=convert_token( line[1].to_i, @new_modules )
            puts "%-35.35s > %-35.35s" % ["", new_str]
        elsif line [1]=="<"
            # only in old file
            clear_unchanged_buffer
            old_str=convert_token( line[0].to_i, @old_modules )
            puts "%-35.35s < %-35.35s" % [old_str, ""]
        elsif line[1]=="|"
            # change
            clear_unchanged_buffer
            old_str=convert_token( line[0].to_i, @old_modules )
            new_str=convert_token( line[2].to_i, @new_modules )
            puts "%-35.35s | %-35.35s" % [old_str, new_str]
        else
            # unchanged
            old_str=convert_token( line[0].to_i, @old_modules )
            new_str=convert_token( line[1].to_i, @new_modules )
            if @compress
                unless @buffer.empty?
                    # If there is something in the buffer it is about to get
                    # destroyed, so count the skipped lines and nodes.
                    @skipped_lines+=1
                    @skipped_nodes+=(@buffer.match( /\((\d+)\)/)[1].to_i rescue 1)
                end
                @buffer=("%-35.35s   %-35.35s" % [old_str, new_str])
            else
                puts "%-35.35s   %-35.35s" % [old_str, new_str]
            end
        end
    end

    private

    def convert_token( token, module_index )
        if token > @seq_dump.grammar.size
            modname, details=module_index.select {|m, d| (d["start"] <= token) && (d["end"] >= token)}[0]
            if modname
                offset=token-details["start"]
                token_str="#{modname}+#{offset.to_s(16)}"
            else
                token_str="???#{token}"
            end
        else
            # It's a rule, because it's too low to be an address.
            # This wouldn't work with kernel code. :)
            unless (rule_length=@rule_length_cache[token])
                rule_length=@seq_dump.expand_rule(token).size
                @rule_length_cache[token]=rule_length
            end
            token_str="#{token} (#{rule_length})"
        end
        token_str
    end

    def clear_unchanged_buffer
        unless @buffer.empty?
            if @skipped_lines > 0
                # the lines that were skipped and forgotten
                puts "       ---------------"
                puts "[... #{@skipped_lines} lines / #{@skipped_nodes} nodes unchanged ...]"
                puts "       ---------------"
            end
            puts @buffer # the last unchanged line
            @buffer=""
            @skipped_lines=0
            @skipped_nodes=0
        end
    end

end

emitter=Emitter.new( SequiturDump.new( opt["grammar"], :lines ), old_modules, new_modules, opt["compress"] )

File.open(opt["d"], "rb") {|ios|
    ios.each_line {|line|
        emitter.handle_line( line )
    }
}

