# Ruby port of a java port of Sequitur. Original copyright below.
# (c) Ben Nagy
#
=begin
This class is part of a Java port of Craig Nevill-Manning's Sequitur algorithm.
Copyright (C) 1997 Eibe Frank

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
=end

class DigramIndex < Hash
    def make_key( node )
        # experiments with the "hashtable value" of the digram
        # go here.
        [node.val,node.next.val]
    end
    def contains?( node )
        raise RuntimeError unless node.kind_of? Node
        !!(self[make_key( node )])
    end

    def lookup( node )
        raise RuntimeError unless node.kind_of? Node
        self[make_key( node )]
    end

    def insert_digram( node )
        raise RuntimeError unless node.kind_of? Node
        raise RuntimeError if node.next.is_guard?
        raise RuntimeError if node.is_guard?
        self[make_key( node )]=node
    end

    def delete_digram( node )
        raise RuntimeError, "#{node.inspect}" unless node.kind_of? Node
        self.delete( make_key( node) )
    end

    def serialize( outfile=$stdout )
        outfile.puts( YAML.dump( self ) )
    end

    def inspect
        self.map {|k,v| "#{v.val.inspect} -> #{k.inspect}\n"}
    end
end

class Node

    attr_reader :prev, :next, :val

    class << self
        @@digram_index||=DigramIndex.new
    end

    def initialize
        @digram_index=@@digram_index
        @prev=@next=nil
    end

    def prev=( other )
        raise RuntimeError unless other.kind_of? Node
        @prev=other
    end

    def next=( other )
        raise RuntimeError unless other.kind_of? Node
        @next=other
    end

    def join( left, right )
        left.delete_digram if left.next
        left.next=right
        right.prev=left
    end

    def cleanup
        # This should be overloaded in all subclasses.
        raise RuntimeError
    end

    def delete_digram
        return if self.next.is_guard?
        # Only delete precise matches. It's possible for the digram values
        # to point to a different node, and those cases get cleaned up
        # elsewhere.
        @digram_index.delete_digram self if @digram_index.lookup( self )==self
    end

    def insert_after( node )
        raise RuntimeError unless node.kind_of? Node
        join( node, self.next )
        join( self, node )
    end

    def is_guard?
        false
    end

    # Checks a new digram. If it appears
    # elsewhere, deals with it by calling
    # handle_match, otherwise inserts it into the
    # hash table.
    def check
        return false if self.next.is_guard?
        existing_match=@digram_index.lookup( self )
        if existing_match
            handle_match( existing_match ) unless existing_match.next==self
            return true
        else
            @digram_index.insert_digram( self )
            return false
        end
    end

    def substitute( rule )
        cleanup
        self.next.cleanup
        new_node=NonTerminal.new( rule )
        self.prev.insert_after( new_node )
        # if the previous node triggers an existing match
        # then handle_match will recurse, and this node will
        # be checked as part of that. Otherwise we need to 
        # check this node as the head of a new digram.
        unless self.prev.check
            new_node.check
        end
    end

    # This method deals with cases where we need to substitute something for
    # a digram. Either there is an existing rule, or this digram has been
    # seen once already.
    def handle_match( existing_match )
        if existing_match.prev.is_guard? and existing_match.next.next.is_guard?
            r=existing_match.prev.rule
            self.substitute r
            if r.first.is_a?( NonTerminal ) && r.first.rule.reference_count<=1
                r.first.expand
            else
                @digram_index.insert_digram(r.first) 
            end
        else
            r=Rule.new( existing_match.clone, existing_match.next.clone )
            existing_match.substitute r
            self.substitute r
            if r.first.is_a?( NonTerminal ) && r.first.rule.reference_count<=1
                r.first.expand
                # if the first element of this rule was a nonterminal
                # that we just expanded, we don't want to insert it
                # into the digram index, since it no longer exists.
                # I don't read Java well, but as far as I can see
                # this logic was not in the Java code, so I wonder if
                # their digram index was bigger than it needed to be?
            else
                # Otherwise, add the new digram to the index.
                @digram_index.insert_digram(r.first) 
            end
        end
    end
end
