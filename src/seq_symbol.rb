# Ruby port of a java port of Sequitur. Original copyright below.
# Many of the orginal comments retained, all I did was ruby-fy stuff.
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
    def contains?( sym )
        raise RuntimeError unless sym.kind_of? Symbol
        !!(self[[sym.val, sym.n.val]])
    end

    def lookup( sym )
        raise RuntimeError unless sym.kind_of? Symbol
        self[[sym.val, sym.n.val]]
    end

    def insert( sym )
        raise RuntimeError unless sym.kind_of? Symbol
        self[[sym.val, sym.n.val]]=sym
    end

    def delete( sym )
        raise RuntimeError unless sym.kind_of? Symbol
        return unless sym.n
        self.delete [sym.val, sym.n.val]
    end
end

class Node

    attr_reader :p, :n, :value 

    class << self
        def digram_index
            @digram_index||=DigramIndex.new {|h,k| h[k]=false}
        end
    end

    def initialize
        @digram_index=self.class.digram_index
    end

    def p=( other )
        raise RuntimeError unless other.kind_of? Symbol
        @p=other
    end

    def n=( other )
        raise RuntimeError unless other.kind_of? Symbol
        @n=other
    end

    def join( left, right )
        if left.n
            @digram_index.delete left
        end
        left.n=right
        right.p=left
    end

    def cleanup
    end

    def insert_after( sym )
        raise RuntimeError unless sym.kind_of? Symbol
        join( sym, self.n )
        join( self, sym )
    end

    def is_guard?
        false
    end

    # Checks a new digram. If it appears
    # elsewhere, deals with it by calling
    # match(), otherwise inserts it into the
    # hash table.
    def check
        return false if self.n.is_guard?
        existing_match=@digram_index.lookup( self )
        if existing_match
            handle_match( existing_match )
            true
        else
            @digram_index.insert( self )
            false
        end
    end

    def substitute( new_rule )
        raise RuntimeError unless new_rule.is_a? Rule
        new=NonTerminal.new( new_rule )
        self.p.insert_after( new )
        self.p.check
        new.check
    end

    def handle_match( existing_match )
        if self.is_a? NonTerminal
            self.rule.reference_count-=1
        end
        if self.n.is_a? NonTerminal
            self.n.rule.reference_count-=1
        end
        if existing_match.is_a? NonTerminal
            self.substitute existing_match.rule
            existing_match.rule.reference_count+=1
        else
            r=Rule.new( existing_match, existing_match.n )
            self.substitute r
            existing_match.substitute r
            if r.first.is_a? NonTerminal && r.first.rule.count==1
                r.first.rule.expand
            end
        end
    end
end









