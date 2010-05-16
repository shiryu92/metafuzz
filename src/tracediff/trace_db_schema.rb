module TraceDBSchema

    def self.setup_schema( sequel_db )

        sequel_db.create_table :transition_types do
            primary_key :id
            String :transition_type
            unique :transition_type
        end unless sequel_db.table_exists? :transition_types

        sequel_db.create_table :modules do
            primary_key :id
            String :name
            Integer :checksum
            Integer :size
            unique :checksum # CRC32 collisions? Could happen I guess...
        end unless sequel_db.table_exists? :modules

        sequel_db.create_table :traces do
            primary_key :id
            DateTime :timestamp
            String :filename
        end unless sequel_db.table_exists? :traces

        sequel_db.create_table :loaded_modules do
            primary_key :id
            foreign_key :trace_id, :traces
            foreign_key :module_id, :modules
            Integer :base
        end unless sequel_db.table_exists? :loaded_modules

        sequel_db.create_table :trace_lines do
            primary_key :id
            foreign_key :trace_id, :traces
            foreign_key :transition_type, :transition_types
            Integer :from
            Integer :to
            Integer :eax
            Integer :ebx
            Integer :ecx
            Integer :edx
            Integer :esp
            Integer :ebp
            Integer :esi
            Integer :edi
            Integer :eip
            Integer :flags
        end unless sequel_db.table_exists? :trace_lines

    end
end
