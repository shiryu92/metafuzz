# Some test code to mark up modules in diffed, sequitur compressed
# output.
# (c) Ben Nagy, 2010

require File.dirname(__FILE__) + '/seq_dump_api'
require 'rubygems'
require "getopt/long"
require 'streamdiff'
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
-g | --grammar  - sequitur output file, containing the grammar
-d | --sdiff_output - output from sdiff -d comparing the node files
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

seq_dump=SequiturDump.new(opt["g"])

class DiffEngine

    class Chunk < Array
        attr_accessor :chunk_type, :offset, :size
        def initialize(chunk_type, *contents)
            @chunk_type=chunk_type
            @size=0
            @offset=0
            super( contents )
        end
        def clear
            @size=0
            super
        end
    end

    class Change
        attr_reader :old_elem, :new_elem, :old_elem_size, :new_elem_size, :action
        def initialize( action, old_elem, new_elem, old_elem_size, new_elem_size )
            @action=action 
            @old_elem=old_elem 
            @new_elem=new_elem 
            @old_elem_size=old_elem_size 
            @new_elem_size=new_elem_size
        end
    end

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

    def diff_and_markup(sdiff_output, ignore_limit=1)
        # The unfortunate truth is that the Ruby Diff::LCS gem is
        # slow as hell, so this method is the only practical way
        # to diff large sets - dump them to files, use unix sdiff -d
        # and then read the output. The result should be equivalent
        # to StreamDiff::diff_and_markup.
        old=[]
        new=[]
        unchanged_buffer=Chunk.new(:buffer)
        diffs=sdiff_output.map {|l| handle_line( l )}
        diffs.each {|change|
            #puts "#{change.action} #{change.old_elem} || #{change.new_elem} #{old.size} #{new.size}"
            case change.action
            when *['+','-','!']
                if unchanged_buffer.length > ignore_limit
                    # There have been more than ignore_limit unchanged
                    # tokens between the last change (or start) and this
                    # change.
                    # add a new unchanged chunk
                    c=Chunk.new( :unchanged, *unchanged_buffer )
                    c.offset=old.last.offset + old.last.size rescue 0
                    c.size=unchanged_buffer.size
                    old << c
                    c=Chunk.new( :unchanged, *unchanged_buffer )
                    c.offset=new.last.offset + new.last.size rescue 0
                    c.size=unchanged_buffer.size
                    new << c
                    # And start a new diff chunk
                    c=Chunk.new( :diff, change.old_elem )
                    c.offset=old.last.offset + old.last.size
                    c.size=change.old_elem_size
                    old << c
                    c=Chunk.new( :diff, change.new_elem )
                    c.offset=new.last.offset + new.last.size
                    c.size=change.new_elem_size
                    new << c
                else
                    if old.empty?
                        old << Chunk.new( :diff )
                        old.last.offset=0
                    end
                    if new.empty?
                        new << Chunk.new( :diff )
                        new.last.offset=0
                    end
                    # So whatever happens now, we have a diff chunk as the
                    # last array element.
                    #
                    # put the ignored, unchanged tokens into the diff chunk
                    # this syntax is ugly, but old.last+=<an array> doesn't
                    # work because of method syntax (it looks for Array#last=)
                    unchanged_buffer.each {|token|
                        old.last << token
                        new.last << token
                    }
                    old.last.size+=unchanged_buffer.size
                    new.last.size+=unchanged_buffer.size
                    # and add the change to this diff chunk
                    old.last << change.old_elem
                    old.last.size+=change.old_elem_size
                    new.last << change.new_elem
                    new.last.size+=change.new_elem_size
                end
                unchanged_buffer.clear
            when '='
                unchanged_buffer << change.old_elem
                unchanged_buffer.size+=change.old_elem_size
            end
        }
        # whatever is left in the unchanged buffer gets tacked on the end.
        unless unchanged_buffer.empty?
            c=Chunk.new( :unchanged, *unchanged_buffer )
            c.offset=old.last.offset + old.last.size
            c.size=unchanged_buffer.size
            old << c
            c=Chunk.new( :unchanged, *unchanged_buffer )
            c.offset=new.last.offset + new.last.size
            c.size=unchanged_buffer.size
            new << c
        end
        [old, new]
    end

    def expand_rule( token, level=-1 )
        begin
            if Integer( token ) <= @seq_dump.grammar.size 
                @seq_dump.expand_rule( token, level )
            else
                [token]
            end
        rescue
            []
        end
    end

    def prettify_token( token, module_index )
        token=Integer( token ) rescue return
        if module_index==:old
            module_index=@old_modules
        elsif module_index==:new
            module_index=@new_modules
        else
            raise ArgumentError, "module_index must be :old or :new"
        end
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
                rule_length=token_size( token )
                @rule_length_cache[token]=rule_length
            end
            token_str="#{token} (#{rule_length})"
        end
        token_str
    end

    private

    def handle_line( line )
        line=line.split
        if line[0]==">"
            # only in new file
            return Change.new( '+', "", line[1], 0, token_size(line[1]))
        elsif line [1]=="<"
            # only in old file
            return Change.new( '-', line[0], "", token_size(line[0]), 0)
        elsif line[1]=="|"
            # change
            return Change.new( '!', line[0], line[2], token_size(line[0]), token_size(line[2]))
        else
            # unchanged
            return Change.new( '=', line[0], line[1], token_size(line[0]), token_size(line[1]))
        end
    end

    def token_size( token )
        if Integer( token ) > @seq_dump.grammar.size
            1
        else
            # It's a rule, because it's too low to be an address.
            # This wouldn't work with kernel code. :)
            unless (rule_length=@rule_length_cache[token])
                rule_length=@seq_dump.expand_rule(token).size
                @rule_length_cache[token]=rule_length
            end
            rule_length
        end
    end
end

e=DiffEngine.new(seq_dump, old_modules, new_modules)
old,new=e.diff_and_markup(File.read(opt["d"]))
old.zip(new).each {|o, n| 
    puts "#{o.chunk_type} at #{o.offset}:#{o.size}(#{o.length}) / #{n.offset}:#{n.size}(#{n.length})"
    if o.length!=n.length
        puts "wtf?"
        p o
        p n
        puts "/wtf"
    end
    if o.chunk_type==:diff
        o.zip(n).each {|pair|
            puts "%-20.20s     %-20.20s" % [e.prettify_token(pair[0],:old),e.prettify_token(pair[1],:new)]
        }
        next
        puts "EXPANDING"
        old_expanded=o.map {|elem| e.expand_rule( elem,2 )}.flatten
        new_expanded=n.map {|elem| e.expand_rule( elem,2 )}.flatten
        old_diffed,new_diffed=StreamDiff.diff_and_markup(old_expanded, new_expanded)
        old_diffed.zip( new_diffed ).each {|od,nd|
            puts "#{od.chunk_type}:#{od.size} -- #{nd.chunk_type}:#{nd.size}"
            next unless od.chunk_type==:diff
            od.zip(nd).each {|a,b| puts "%-20.20s   %-20.20s" % [e.prettify_token(a,:old),e.prettify_token(b,:new)]}
        }
    end
}
