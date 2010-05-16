require 'rubygems'
require 'dynrio_dump_api'

# SEQUITUR parsed output, including deflated old and new seqs
# as well as the grammar. This is generated from a pre-processed
# file which converts all control transfers to "nodes" such that
# a call TO a function creates a node, and a RET to the same
# function, whose actual EIP will be 4-8 bytes greater, will be 
# the same node.
dump=SequiturDump.new(ARGV[0])
# Raw DynRIO dumps, which have full state
old_full=DynRIODump.new(ARGV[1])
new_full=DynRIODump.new(ARGV[2])

# quick test
for i in (0..6)
    expanded_old=dump.expand_rule( dump.old[i] ) rescue dump.old[i]
    expanded_new=dump.expand_rule( dump.new[i] ) rescue dump.new[i]
    unless expanded_old==expanded_new
        puts "Rule mismatch! at #{i}"
        p expanded_old
        p dump.expand_rule(dump.old[i+1])[0..5]
        p expanded_new
        break
    end
    unless expanded_old.is_a? Array
        next
    end

    for j in 0..expanded_old.length-1 do
        old_state=old_full.get_record( j )
        new_state=new_full.get_record( j )
        addresses_same=((old_state["from"]==new_state["from"]) and (old_state["to"]==new_state["to"]))
        #next if addresses_same
        state_same=old_state["state"]==new_state["state"]
        puts "#{expanded_old[j]} / #{expanded_new[j]} @ #{j}: Addresses #{addresses_same}, state #{state_same}"
        unless state_same
            puts "Old: #{old_state.inspect}"
            puts "New: #{new_state.inspect}"
        end
    end
end
