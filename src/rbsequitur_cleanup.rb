require 'doubly_linked_list'
input=File.read ARGV[0]
#for this quick test we will assume the input is a string and break it into
#bytes.
symbols=input.strip.split('')

class Grammar < Array
    attr_accessor :counter
end

class Rule
    attr_accessor :rule_number, :containers
    def initialize( rule_number, digram_index )
        @number=rule_number
        @guard_node=ListNode.new(value=rule_number, guard=true)
        @digram_index=digram_index
        # all the listnodes that contain me. Updated in ListNode#initialize.
        @containers=[] 
    end

    def reference_count
        @containers.size
    end

    def last_node
        @guard_node.prev
    end

    def first_node
        @guard_node.next
    end

    def insert_after( target, node )
        node.prev=target
        node.next=target.next
        target.next.prev=node
        target.next=node
    end

    def <<(item)
        new_node=ListNode.new(item)
        new_node.tag=@number
        insert_after( last_node, new_node )
    end

    def sequence
        seq=[]
        node=@guard_node
        until node.next.is_guard?
            node=node.next
            seq << node.value
        end
        seq
    end

    def expand
        puts "EXPANDING rule #{self.inspect}->#{self.sequence.inspect} now..."
        # this rule is now only contained in one node, which makes its
        # reference count 1, so we expand it in place, as per the algorithm
        # now we will splice our sequence in to replace
        # the rule entry
        node_to_expand=@containers.first
        # There are some digrams that need to be deleted. The first two
        # are xR and Rx where R is the rule being expanded. The last one
        # is [x,y]->R where R is the rule to expand.
        @digram_index.delete [self,node_to_expand.next.value] 
        @digram_index.delete [node_to_expand.prev.value, self]
        my_seq_head=self.first_node
        my_seq_tail=self.last_node
        # Fix up pointers to splice the sequence in
        node_to_expand.prev.next=my_seq_head
        my_seq_head.prev=node_to_expand.prev
        my_seq_tail.next=node_to_expand.next
        node_to_expand.next.prev=my_seq_tail
        # No need to call destroy, because that will check utility again etc
        node_to_expand.value=nil
        node_to_expand.prev=node_to_expand.next=nil
    end

    def check_utility
        # called in ListNode#destroy
        if reference_count == 1
            expand
            $grammar.delete self
        end
    end

    def remove_old_links( first_replaced_node, last_replaced_node, replacement_node )
        # check broken digram links. If we had abxxxxxcd and we now have aR1d then the
        # old digrams ab and cd don't point there anymore (they may exist elsewhere
        # if K > 1). In the case given first_node would contain 'b', first_node.prev
        # contains 'a' etc...
        unless first_replaced_node.prev.is_guard?
            # abc-> aR1, remove ab
            digram=[first_replaced_node.prev.value, first_replaced_node.value]
            @digram_index[digram].delete first_replaced_node.prev
            if @digram_index[digram].empty?
                @digram_index.delete digram
            end
        end

        unless last_replaced_node.next.is_guard?
            # bcd-> R1d, remove cd
            digram=[last_replaced_node.value, last_replaced_node.next.value]
            @digram_index[digram].delete last_replaced_node
            if @digram_index[digram].empty?
                @digram_index.delete digram
            end
        end
    end

    def add_new_links( new_node )
        # check broken digram links. If we had abxxxxxcd and we now have aR1d then the
        # old digrams ab and cd don't point there anymore (they may exist elsewhere
        # if K > 1). In the case given first_node would contain 'b', first_node.prev
        # contains 'a' etc...
        begin
            unless new_node.prev.is_guard?
                # add [prev, new] to the index and recurse
                digram=[new_node.prev.value, new_node.value]
                @digram_index[[new_node.prev.value, new_node.value]] << new_node.prev
                digram_locations=@digram_index[[new_node.prev.value, new_node.value]]
                if (existing_rule=digram_locations.first).is_a? Rule
                    # replace with existing rule
                    replace_digram_with( digram.first, existing_rule ) 
                elsif digram_locations.size > K
                    # create a new rule
                    $grammar.counter+=1
                    new_rule=Rule.new($grammar.counter, @digram_index)
                    digram.each {|val| new_rule << val}
                    $grammar << new_rule
                    # replace all occurrences of the digram with the rule
                    digram_locations.each {|digram_head|
                        replace_digram_with( digram_head, new_rule )
                    }
                end
            end
        rescue
            puts "rescued"
        end
        begin
            unless new_node.next.is_guard?
                # add [new, next] to the index and recurse
                digram=[new_node.value, new_node.next.value]
                @digram_index[[new_node.value, new_node.next.value]] << new_node
                digram_locations=@digram_index[[new_node.value, new_node.next.value]]
                if (existing_rule=digram_locations.first).is_a? Rule
                    # replace with existing rule
                    replace_digram_with( digram.first, existing_rule ) 
                elsif digram_locations.size > K
                    # create a new rule
                    $grammar.counter+=1
                    new_rule=Rule.new($grammar.counter, @digram_index)
                    digram.each {|val| new_rule << val}
                    $grammar << new_rule
                    # replace all occurrences of the digram with the rule
                    digram_locations.each {|digram_head|
                        replace_digram_with( digram_head, new_rule )
                    }
                end
            end
        rescue
            puts "rescued"
        end
    end

    def replace_digram_with( first_node, new_rule )
        if first_node.next.is_guard?
            raise RuntimeError, "Rule: digram head doesn't have anything following it"
        end
        puts "replacing #{first_node.inspect} with #{new_rule.inspect}"
        # Two nodes get "deleted" and a new node gets 
        # inserted. 
        # first_node is the first node of the digram being replaced
        # in this rule
        new_node=ListNode.new(new_rule)
        new_node.tag=@number
        # Check and possibly update the surrounding links
        remove_old_links( first_node, first_node.next, new_node )
        # Add the link to the digram we just replaced with a rule
        @digram_index[[first_node.value, first_node.next.value]]=[new_rule]
        # Update the pointers
        new_node.prev=first_node.prev
        new_node.next=first_node.next.next
        first_node.prev.next=new_node
        first_node.next.next.prev=new_node
        # Destroy the nodes we just replaced (which will also then check rule
        # utility if either of those nodes contained rules)
        first_node.next.destroy
        first_node.destroy
        puts "about to check links to #{new_node.inspect}"
        add_new_links( new_node )
        puts "Replacing done"
        p sequence
        new_node
    end

    def inspect
        "R#{@number}"
    end
end

# How often must a digram appear before it is replaced
# by a rule? Defaults to twice.
K=1

# node is the first node of a digram, digram_index is a global
# hash used to keep track of the digrams
def add_and_check_digrams(rule, node, digram_index)
    puts "Starting add_and_check, seq is #{rule.sequence.inspect}"
    digram=[node, node.next]
    digram_values=[node.value, node.next.value]
    puts "This digram is #{digram.inspect}"
    digram_locations=digram_index[digram_values]
    if (existing_rule=digram_locations.first).is_a? Rule
        # replace with existing rule
        puts "Main loop, replace with existing"
        replacement=rule.replace_digram_with( digram.first, existing_rule ) 
        puts "main replace done"
    elsif digram_locations.size+1 > K
        # create a new rule
        $grammar.counter+=1
        new_rule=Rule.new($grammar.counter, digram_index)
        digram_values.each {|val| new_rule << val}
        $grammar << new_rule
        digram_locations << digram.first
        # replace all occurrences of the digram with the rule
        digram_locations.each {|digram_head|
            puts "Main loop, replace with new"
            replacement=rule.replace_digram_with( digram_head, new_rule )
            puts "main replace new done"
        }
    else
        # Not more than K occurrences yet.
        # Add this node to the list of digram locations
        digram_locations << node
    end
    puts "Leaving. seq is now #{rule.sequence.inspect}"
end

def dump_rules
    $grammar.each {|rule|
        puts "#{rule.inspect} -> #{rule.sequence.inspect} (#{rule.containers.inspect})"
    }
end

def dump_digram_index( d_idx )
    d_idx.each {|k,v| puts "#{k.inspect} -> #{v.inspect}"}
end

digram_index=Hash.new {|h,k| h[k]=[]}
$grammar=Grammar.new
$grammar.counter=0
main_rule=Rule.new( $grammar.counter, digram_index )
$grammar << main_rule
main_rule << symbols.shift # read first symbol - no digrams yet
symbols.each {|sym|
    puts "Appending sym #{sym} to main sequence"
    main_rule << sym
    add_and_check_digrams( main_rule, main_rule.last_node.prev, digram_index)
    puts "DONE for this sym."
    dump_rules
    dump_digram_index( digram_index )
}


