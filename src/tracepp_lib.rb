require File.dirname(__FILE__) + '/binstruct'
require File.dirname(__FILE__) + '/differ'

module TracePP

    class TraceLine < Binstruct

        TYPE_HASH={
            "CALL"=>0,
            "CALL INDIRECT"=>1,
            "RETURN"=>2
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

        attr_reader :module_index_template, :module_index_new

        def initialize( template_fname, old_fname, new_fname )
            @template_stem=File.join(File.dirname(template_fname),File.basename(template_fname, ".txt"))
            @new_stem=File.join(File.dirname(new_fname),File.basename(new_fname, ".txt"))
            @old_stem=File.join(File.dirname(old_fname),File.basename(old_fname, ".txt"))
            @grammar=Grammar.new(@template_stem + ".pp.grammar.txt")
            @module_index_old=OklahomaMixer.open( @old_stem + ".pp.mod.tch", :mode=>"r" )
            unless new_fname==old_fname
                @module_index_new=OklahomaMixer.open( @new_stem + ".pp.mod.tch" , :mode=>"r")
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

        def prettify_token( token, module_index={} )
            return token if token==nil or token==""
            if token[0]=='&'
                begin
                    modname, details=module_index.select {|m, d| (Integer(d["start"]) <= Integer(token)) && (Integer(d["end"]) >= Integer(token))}[0]
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
