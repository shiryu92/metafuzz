module ResultDBSchema

    def self.setup_schema( sequel_db )

        sequel_db.create_table :results do
            primary_key :id
            foreign_key :result_id, :result_strings
        end unless sequel_db.table_exists? :results

        sequel_db.create_table :crashes do
            primary_key :id
            foreign_key :result_id, :results
            column :timestamp, :datetime
            foreign_key :hash_id, :hash_strings
            foreign_key :desc_id, :descs
            foreign_key :type_id, :types
            foreign_key :classification_id, :classifications
            foreign_key :template_id, :templates
        end unless sequel_db.table_exists? :crashes

        sequel_db.create_table :loaded_modules do
            primary_key :id
            foreign_key :crash_id, :crashes
            foreign_key :module_id, :modules
        end

        sequel_db.create_table :modules do
            primary_key :id
            column :name, :string
            column :hash, :string
            column :version, :string
        end unless sequel_db.table_exists? :modules

        sequel_db.create_table :functions do
            primary_key :id
            foreign_key :module_id, :modules
            column :name, :string
            column :address, :integer
        end unless sequel_db.table_exists? :functions

        sequel_db.create_table :stackframes do
            primary_key :id
            foreign_key :stacktrace_id, :stacktraces
            foreign_key :function_id, :functions
            column :address, :integer
            coulmn :sequence, :integer
        end unless sequel_db.table_exists? :frames

        sequel_db.create_table :stacktraces do
            primary_key :id
            foreign_key :crash_id, :crashes
        end unless sequel_db.table_exists? :stack_traces

        sequel_db.create_table :register_dumps do
            primary_key :id
            foreign_key :crash_id, :crashes
            column :eax, :integer
            column :ebx, :integer
            column :ecx, :integer
            column :edx, :integer
            column :esp, :integer
            column :ebp, :integer
            column :esi, :integer
            column :edi, :integer
            column :eip, :integer
        end unless sequel_db.table_exists? :register_dumps

        sequel_db.create_table :diffs do
            primary_key :id
            foreign_key :crash_id, :crashes
            foreign_key :stream_id, :streams
            column :offset, :integer
            column :old_val, :string
            column :new_val, :string
        end unless sequel_db.table_exists? :diffs

        sequel_db.create_table :disasm do
            primary_key :id
            foreign_key :crash_id, :crashes
            column :seq, :integer
            column :address, :string
            column :asm, :string
        end unless sequel_db.table_exists? :disasm

        sequel_db.create_table :streams do
            primary_key :id
            column :name, :string
        end unless sequel_db.table_exists? :streams

        sequel_db.create_table :descs do
            primary_key :id
            column :desc, :string
        end unless sequel_db.table_exists? :descs

        sequel_db.create_table :exception_types do
            primary_key :id
            column :exception_type, :string
        end unless sequel_db.table_exists? :exception_types

        sequel_db.create_table :exception_subtypes do
            primary_key :id
            column :exception_subtype, :string
        end unless sequel_db.table_exists? :exception_subtypes

        sequel_db.create_table :classifications do
            primary_key :id
            column :classification, :string
        end unless sequel_db.table_exists? :classifications

        # This actually stores the template hash
        # The template itself is on disk, but if I called it
        # template_hashes it would cause problems for the
        # id_for_string function. Lame.
        sequel_db.create_table :templates do
            primary_key :id
            column :template, :string
            unique :template
        end unless sequel_db.table_exists? :templates

        sequel_db.create_table :hash_strings do
            primary_key :id
            column :hash_string, :string
        end unless sequel_db.table_exists? :hash_strings

        sequel_db.create_table :result_strings do
            primary_key :id
            column :result_string, :string
        end unless sequel_db.table_exists? :result_strings
    end
end
