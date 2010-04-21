# Prototype code to "recompress" sequences with a saved Sequitur grammar
# (c) Ben Nagy, 2010
require File.dirname(__FILE__) + '/grammar'

class Recompressor

    # For reading large files, uses less memory.
    class Stream < Array
        def initialize( fh, &read_block)
            @fh=fh
            # For example, to read lines, read_block could be
            # {|fh| fh.readline.chomp}
            # And for characters
            # {|fh| fh.getc.chr}
            @read_block=read_block
        end

        def next_token
            begin
                @read_block.call( @fh )
            rescue
                nil
            end
        end

        def shift
            return next_token if self.empty?
            super
        end

        def close
            @fh.close
        end
    end

    def initialize( grammar )
        raise ArgumentError, "Bad saved grammar." unless grammar.kind_of? Grammar
        # Build the Recompressor from the saved grammar
        # This builds a Trie, which is a bit crap.
        # I need to work out how to make it use a minimized directed graph
        # and then add the node state required for 'perfect hashing'
        @graph_head=RecompressorNode.new( nil )
        for idx in 1..grammar.size-1
            active_node=@graph_head
            grammar.expand_rule( idx ).each {|token|
                active_node=active_node.traverse(token, build=true)
            }
            active_node.terminal=idx
        end
    end

    # Recompressor doesn't close the filehandle if you are using the Stream class,
    # that's the caller's job.
    def recompress( unprocessed )
        emitted, residue=recompress_with_remainder( unprocessed )
        # There are a few cases where the buffer in the recompress method
        # still holds data that can be compressed, so we have to recurse 
        # on the residue.
        until residue.empty?
            extra, residue=recompress_with_remainder( residue )
            emitted.push *extra
            emitted.push residue.shift unless residue.empty?
        end
        emitted
    end

    private 

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
            if next_node=exits[token]
                next_node
            elsif build
                exits[token]=RecompressorNode.new( token )
            else
                false
            end
        end

        def inspect
            "T:#{token} #{exits.keys.inspect}#{self.is_terminal?? "!(#{@terminal})" : ''}"
        end
    end

    def recompress_with_remainder( unprocessed ) 
        active_node=@graph_head
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
                    buffer.clear
                else
                    buffer << token
                end
            else
                # We couldn't match this token at the start of the Recompressor
                # so just emit it.
                if active_node==@graph_head
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
                    active_node=@graph_head
                    buffer.clear
                end
            end
        end
        emitted.push *checkpoint if checkpoint
        [emitted, buffer]
    end

end
