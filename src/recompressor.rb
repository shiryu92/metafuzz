# Prototype code to "recompress" sequences with a saved Sequitur grammar
# (c) Ben Nagy, 2010
require File.dirname(__FILE__) + '/grammar'
require 'rubygems'
require 'oklahoma_mixer'

class Recompressor

    class Trie
        attr_accessor :db
        def initialize( db_filename )
            if File.exists?( db_filename )
                @db=OklahomaMixer.open(db_filename)
                @node=0
            else
                @db=OklahomaMixer.open( db_filename )
                @db.store("global:node_id",1,:add)
                @node=0
            end
        end

        def at_terminal?
            @db.has_key? "terminal:#{@node}"
        end

        def reset
            @node=0
        end

        def current_node
            @node
        end

        def current_terminal
            @db["terminal:#{@node}"]
        end

        def set_terminal( idx )
            @db["terminal:#{@node}"]=idx
        end

        def traverse( token, build=false )
            if new_node_id=@db["#{@node}:#{token}"]
                @node=new_node_id
                true
            elsif build
                new_id=@db.store("global:node_id",1,:add)
                @db["#{@node}:#{token}"]=new_id
                @node=new_id
                true
            else
                false
            end
        end

        def close
            @db.close
        end
    end

    # For reading large files, uses less memory.
    class Stream < Array
        def initialize( fname, &read_block)
            @fh=File.open(fname, "rb")
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

    def initialize( grammar, trie, build=false )
        raise ArgumentError, "Bad saved grammar." unless grammar.kind_of? Grammar
        raise ArgumentError, "Bad saved Trie." unless trie.kind_of? Trie
        @trie=trie
        if build
            # Build the Trie from the saved grammar
            for idx in 1..grammar.size-1
                @trie.reset
                grammar.expand_rule( idx ).each {|token|
                    @trie.traverse(token, build=true)
                }
                @trie.set_terminal( idx )
            end
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

    def recompress_with_remainder( unprocessed ) 
        @trie.reset
        checkpoint=false
        buffer=[]
        emitted=[]
        while token=unprocessed.shift
            # The order of data is
            # emitted <- buffer <- token <- unprocessed
            if @trie.traverse( token )
                # This transition is in the state machine.
                # 1. add the token to the buffer
                # 2. If this token is the last token in a complete rule,
                #    save a checkpoint. If the match continues, the 
                #    checkpoint will be overwritten with the longest
                #    complete match so far.
                if @trie.at_terminal?
                    checkpoint=@trie.current_terminal
                    buffer.clear
                else
                    buffer << token
                end
            else
                # We couldn't match this token at the start of the Recompressor
                # so just emit it.
                if @trie.current_node==0
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
                    @trie.reset
                    buffer.clear
                end
            end
        end
        emitted.push *checkpoint if checkpoint
        [emitted, buffer]
    end

end
