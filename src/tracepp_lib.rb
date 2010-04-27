require File.dirname(__FILE__) + '/binstruct'

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

end
