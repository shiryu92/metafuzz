# Ruby port of a java port of Sequitur. Original copyright below.
# (c) 2010, Ben Nagy
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

require 'seq_guard'

class Grammar < Array

    attr_reader :rule_count

    def initialize
        @rule_count=0
        super
    end

    def <<( other )
        @rule_count+=1
        super
    end

    def serialize( outfile=$stdout )
        outfile.puts( YAML.dump(self) )
    end
end

class Rule

    attr_accessor :reference_count
    attr_reader :grammar

    class << self
        @@grammar||=Grammar.new
    end

    def initialize( first_node=nil, second_node=nil )
        @grammar=@@grammar
        @guard=GuardNode.new( self )
        if first_node.kind_of?( Node ) && second_node.kind_of?( Node )
            @guard.next=first_node
            @guard.prev=second_node
            first_node.next=second_node
            first_node.prev=@guard
            second_node.next=@guard
            second_node.prev=first_node
        else
            @guard.next=@guard
            @guard.prev=@guard
        end
        self.grammar << self
        @reference_count=0
        @number=grammar.index( self )
    end

    def first
        @guard.next
    end

    def last
        @guard.prev
    end

    def number
        self.grammar.index( self )
    end

    def sequence
        node=@guard
        seq=[]
        until node.next.is_guard?
            node=node.next
            seq << node.val
        end
        seq
    end

    def expand( level_limit=-1, level=0 )
        sequence.map {|e|
            if e.is_a?( Rule ) && (level_limit==-1 || level < level_limit)
                e.expand( level_limit, level+1 )
            else
                e
            end
        }.flatten
    end

    def inspect
        "R#{number}"
    end
end
