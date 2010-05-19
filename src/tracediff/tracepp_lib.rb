require 'rubygems'
require 'oklahoma_mixer'
require File.dirname(__FILE__) + '/../binstruct'
require File.dirname(__FILE__) + '/differ'
require File.dirname(__FILE__) + '/grammar'

module TracePP

    TI=".pp.ti.tch"
    TIS=".pp.tis.txt"
    MOD=".pp.mod.tch"
    RAW=".pp.raw.tcf"
    GRAMMAR=".pp.grammar.txt"
    RTIS=".pp.rtis.txt"
    TRIE=".pp.trie.tch"
    SDIFF=".pp.sdiff.txt"

    class TraceLine < Binstruct

        TYPE_HASH={
            "CALL"=>1,
            "CALL INDIRECT"=>2,
            "RETURN"=>3
        }

        INT_HASH=TYPE_HASH.invert

        def self.type_to_int( arg )
            TYPE_HASH[arg]
        end

        def self.int_to_type( arg )
            INT_HASH[arg]
        end

        def self.pack_string; "cNNNNNNNNNNNN"; end

        parse {|buf|
            unsigned buf, :type, 8, "Entry type"
            unsigned buf, :from, 32, "From address"
            unsigned buf, :to, 32, "To address"
            unsigned buf, :eax, 32, "eax"
            unsigned buf, :ebx, 32, "ebx"
            unsigned buf, :ecx, 32, "ecx"
            unsigned buf, :edx, 32, "edx"
            unsigned buf, :esp, 32, "esp"
            unsigned buf, :ebp, 32, "ebp"
            unsigned buf, :esi, 32, "esi"
            unsigned buf, :edi, 32, "edi"
            unsigned buf, :flags, 32, "flags"
            unsigned buf, :hit_count, 32, "Hit count"
        }
    end

    class TracePPDiffer < Differ

        attr_reader :module_index_old, :module_index_new, :grammar

        def initialize( template_fname, old_fname, new_fname )
            @template_stem=File.join(File.dirname(template_fname),File.basename(template_fname, ".txt"))
            @new_stem=File.join(File.dirname(new_fname),File.basename(new_fname, ".txt"))
            @old_stem=File.join(File.dirname(old_fname),File.basename(old_fname, ".txt"))
            @ti=OklahomaMixer.open(@template_stem + TI, :rcnum=>100000000)
            @grammar=Grammar.new(@template_stem + GRAMMAR)
            @module_index_old=OklahomaMixer.open( @old_stem + MOD, :mode=>"r" )
            @raw_old=OklahomaMixer.open( @old_stem + RAW, :mode=>"r", :rcnum=>1000000 )
            if new_fname==old_fname
                # Otherwise we're trying to open twice from the same process and it will barf.
                @module_index_new=@module_index_old
                @raw_new=@raw_old
            else
                @module_index_new=OklahomaMixer.open( @new_stem + MOD, :mode=>"r")
                @raw_new=OklahomaMixer.open( @new_stem + RAW, :mode=>"r", :rcnum=>1000000 )
            end
            @rule_length_cache={}
        end

        def token_size( token )
            return 0 if token==nil or token==""
            begin
                if token[0]=='&'
                    1
                else
                    # It's a rule
                    token=Integer(token)
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

        def hit_count( which_db, tuple_offset )
            raw_db=instance_variable_get( "@raw_#{which_db.to_s}" )
            record=raw_db[ tuple_offset+1 ]
            hit_count=record.unpack( TraceLine.pack_string )[12] # lame but faster
        end

        def full_record( which_db, tuple_offset )
            raw_db=instance_variable_get( "@raw_#{which_db.to_s}" )
            record=raw_db[ tuple_offset+1 ]
            TraceLine.new( record )
        end

        def prettify_token( which_db, token )
            return token if token==nil or token==""
            module_index=instance_variable_get( "@module_index_#{which_db.to_s}" )
            if token[0]=='&'
                # It's an entry in the TI
                begin
                    tuple_index=token[1..-1]
                    tuple=@ti[tuple_index]
                    from, to=tuple.split("->")
                    from_pretty, to_pretty=[Integer(from), Integer(to)].map {|addr|
                        match=module_index.select {|k,v|
                            start, finish, sum=v.split.map(&:to_i)
                            (start<= addr) && (finish >=addr)
                        }[0]
                        # match looks like ["module.dll", "656556 564534 453543"]
                        # where the numbers are start, finish and checksum
                        if match
                            offset=addr - Integer(match[1].split[0])
                            "#{match[0].sub('.dll','')}+#{offset.to_s(16)}"
                        else
                            "#{addr}"
                        end
                    }
                    if which_db==:new
                        # check if this tuple is above orig_max
                        @max||=@ti.store("globals:max_orig_id", 0, :add)
                        if tuple_index.to_i > @max
                            token_str="#{from_pretty} => #{to_pretty}"
                        else
                            token_str="#{from_pretty} -> #{to_pretty}"
                        end
                    else
                        token_str="#{from_pretty} -> #{to_pretty}"
                    end
                rescue
                    warn $!
                    token_str="??#{token}"
                end
            else
                # It's a rule
                unless (rule_length=@rule_length_cache[token])
                    rule_length=token_size( token )
                    @rule_length_cache[token]=rule_length
                end
                token_str="#{token} (#{rule_length})"
            end
            token_str
        end
    end # class TracePPDiffer

end
