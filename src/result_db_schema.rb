module ResultDBSchema

    def self.setup_schema( sequel_db )

        sequel_db.create_table :streams do
            primary_key :id
            String :name
        end unless sequel_db.table_exists? :streams

        sequel_db.create_table :descs do
            primary_key :id
            String :desc
        end unless sequel_db.table_exists? :descs

        sequel_db.create_table :exception_types do
            primary_key :id
            String :exception_type
        end unless sequel_db.table_exists? :exception_types

        sequel_db.create_table :exception_subtypes do
            primary_key :id
            String :exception_subtype
        end unless sequel_db.table_exists? :exception_subtypes

        sequel_db.create_table :classifications do
            primary_key :id
            String :classification
        end unless sequel_db.table_exists? :classifications

        # This actually stores the template hash
        # The template itself is on disk, but if I called it
        # template_hashes it would cause problems for the
        # id_for_string function. Lame.
        sequel_db.create_table :templates do
            primary_key :id
            String :template
            unique :template
        end unless sequel_db.table_exists? :templates

        sequel_db.create_table :hash_strings do
            primary_key :id
            String :hash_string
        end unless sequel_db.table_exists? :hash_strings

        sequel_db.create_table :result_strings do
            primary_key :id
            String :result_string
        end unless sequel_db.table_exists? :result_strings

        sequel_db.create_table :results do
            primary_key :id
            foreign_key :result_id, :result_strings
        end unless sequel_db.table_exists? :results

        sequel_db.create_table :crashes do
            primary_key :id
            foreign_key :result_id, :results
            DateTime :timestamp
            foreign_key :hash_id, :hash_strings
            foreign_key :desc_id, :descs
            foreign_key :exception_subtype_id, :exception_subtypes
            foreign_key :exception_type_id, :exception_types
            foreign_key :classification_id, :classifications
            foreign_key :template_id, :templates
        end unless sequel_db.table_exists? :crashes

        sequel_db.create_table :stacktraces do
            primary_key :id
            foreign_key :crash_id, :crashes
        end unless sequel_db.table_exists? :stacktraces

        sequel_db.create_table :modules do
            primary_key :id
            String :name
            String :hash
            String :version
        end unless sequel_db.table_exists? :modules

        sequel_db.create_table :loaded_modules do
            primary_key :id
            foreign_key :crash_id, :crashes
            foreign_key :module_id, :modules
        end unless sequel_db.table_exists? :loaded_modules

        sequel_db.create_table :functions do
            primary_key :id
            foreign_key :module_id, :modules
            String :name
            Integer :address
        end unless sequel_db.table_exists? :functions

        sequel_db.create_table :stackframes do
            primary_key :id
            foreign_key :stacktrace_id, :stacktraces
            foreign_key :function_id, :functions
            Integer :address
            Integer :sequence
        end unless sequel_db.table_exists? :stackframes

        sequel_db.create_table :register_dumps do
            primary_key :id
            foreign_key :crash_id, :crashes
            Integer :eax
            Integer :ebx
            Integer :ecx
            Integer :edx
            Integer :esp
            Integer :ebp
            Integer :esi
            Integer :edi
            Integer :eip
        end unless sequel_db.table_exists? :register_dumps

        sequel_db.create_table :diffs do
            primary_key :id
            foreign_key :crash_id, :crashes
            foreign_key :stream_id, :streams
            Integer :offset
            String :old_val
            String :new_val
        end unless sequel_db.table_exists? :diffs

        sequel_db.create_table :disasm do
            primary_key :id
            foreign_key :crash_id, :crashes
            Integer :seq
            String :address
            String :asm
        end unless sequel_db.table_exists? :disasm

    end
end
