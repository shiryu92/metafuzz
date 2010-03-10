# Ruby port of a java port of Sequitur. Original copyright below.
# (c) 2010,  Ben Nagy
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

require 'seq_node'

class NonTerminal < Node
    attr_reader :rule
    def initialize( rule )
        @rule=rule
        @rule.reference_count+=1
        @val=rule
        super()
    end

    def expand
        # splice our rule's sequence into whatever linked list we
        # appear in, given that is the last place this rule is used.
        join prev, rule.first
        join rule.last, self.next
        rule.grammar.delete rule
        # In some cases the delete_digram in cleanup isn't enough.
        # I don't know why :(
        delete_digram
    end

    def cleanup
        join self.prev, self.next
        @rule.reference_count-=1
        delete_digram
    end

    def clone
        # by creating a new NonTerminal the rule reference_count
        # will be increased.
        new=NonTerminal.new( @rule )
        new.next=self.next
        new.prev=self.prev
        new
    end


    def inspect
        "#{self.object_id}NT<#{@val.number}>"
    end
end
