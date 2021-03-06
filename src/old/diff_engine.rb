require File.dirname(__FILE__) + '/grammar'
require 'rubygems'
require 'diff/lcs'

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
            @offset=0
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

    def initialize( grammar )
        @grammar=grammar
        @rule_length_cache={}
    end

    def changes_to_chunks( diffs, ignore_limit )
        old=[]
        new=[]
        unchanged_buffer=Chunk.new(:buffer)
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
                    #unchanged_buffer.each {|token|
                    #    old.last << token
                    #    new.last << token
                    #}
                    old.last.push *unchanged_buffer
                    new.last.push *unchanged_buffer
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

    # For Strings or Arrays.
    def diff_and_markup(s1, s2, ignore_limit=1)
        diffs=Diff::LCS.sdiff(s1, s2).map {|lcs_change| handle_lcs_change( lcs_change ) }
        changes_to_chunks( diffs, ignore_limit )
    end

    # For sdiff output. Don't split it in advance!!
    def sdiff_markup(sdiff_output, ignore_limit=1)
        # The unfortunate truth is that the Ruby Diff::LCS gem is
        # slow as hell, so this method is the only practical way
        # to diff large sets - dump them to files, use unix sdiff -d
        # and then read the output. The result should be equivalent
        # to diff_and_markup.
        diffs=[]
        sdiff_output.each_line {|l| diffs.push(handle_sdiff_line( l ))}
        changes_to_chunks( diffs, ignore_limit )
    end

    def expand_rule( token, level=-1 )
        begin
            if Integer( token ) <= @grammar.size 
                @grammar.expand_rule( token, level )
            else
                [token]
            end
        rescue
            puts $!
            []
        end
    end

    def prettify_token( token, module_index={} )
        token=Integer( token ) rescue return
        if token > @grammar.size
            begin
                modname, details=module_index.select {|m, d| (d["start"] <= token) && (d["end"] >= token)}[0]
                if modname
                    offset=token-details["start"]
                    token_str="#{modname}+#{offset.to_s(16)}"
                else
                    token_str="???#{token}"
                end
            rescue
                token_str=token
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

    def handle_sdiff_line( line )
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

    def handle_lcs_change( lcs_change )
        Change.new( 
                   lcs_change.action,
                   lcs_change.old_element.to_s,
                   lcs_change.new_element.to_s,
                   token_size(lcs_change.old_element),
                   token_size(lcs_change.new_element)
                  )
    end

    def token_size( token )
        return 0 if token==nil or token==""
        begin
            if Integer( token ) > @grammar.size
                1
            else
                # It's a rule, because it's too low to be an address.
                # This wouldn't work with kernel code. :)
                unless (rule_length=@rule_length_cache[token])
                    rule_length=@grammar.expand_rule(token).size
                    @rule_length_cache[token]=rule_length
                end
                rule_length
            end
        rescue
            # Who knows what they're trying to diff now?
            if token.respond_to? :size
                token.size 
            else
                1
            end
        end
    end
end

