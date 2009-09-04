#require File.dirname(__FILE__) + '/rtdbwrapper'
require File.dirname(__FILE__) + '/detail_parser'

# Just a quick wrapper, so I can change the underlying DB.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
module MetafuzzDB

  class ResultDB
    def initialize(params)

      @db.create_table :results do
        primary_key :id
        foreign_key :result_id, :result_strings
      end unless @db.table_exists? :results

      @db.create_table :crashes do
        primary_key :id
        foreign_key :result_id, :results
        column :hash, :string
        column :timestamp, :datetime
        foreign_key :desc_id, :descs
        foreign_key :type_id, :types
        foreign_key :classification_id, :classifications
      end unless @db.table_exists? :crashes

      @db.create_table :crash_files do
        primary_key :id
        foreign_key :crash_id, :crashes
        column :crashdetail_path, :string
        column :crashfile_path, :string
      end unless @db.table_exists? :crash_files

      @db.create_table :modules do
        primary_key :id
        column :name, :string
        column :path, :string
        column :version, :string
      end unless @db.table_exists? :modules

      @db.create_table :functions do
        primary_key :id
        foreign_key :module_id, :modules
        column :name, :string
        column :address, :integer
      end unless @db.table_exists? :functions

      @db.create_table :stackframes do
        primary_key :id
        foreign_key :stacktrace_id, :stacktraces
        foreign_key :function_id, :functions
        column :address, :integer
        coulmn :sequence, :integer
      end unless @db.table_exists? :frames

      @db.create_table :stacktraces do
        primary_key :id
        foreign_key :crash_id, :crashes
      end unless @db.table_exists? :stack_traces

      @db.create_table :register_dumps do
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
      end unless @db.table_exists? :register_dumps

      @db.create_table :diffs do
        primary_key :id
        foreign_key :crash_id, :crashes
        foreign_key :stream_id, :streams
        column :offset, :integer
        column :old_val, :string
        column :new_val, :string
      end unless @db.table_exists? :diffs

      @db.create_table :disasm do
        primary_key :id
        foreign_key :crash_id, :crashes
        column :seq, :integer
        column :address, :string
        column :asm, :string
      end unless @db.table_exists? :disasm

      @db.create_table :streams do
        primary_key :id
        column :name, :string
      end unless @db.table_exists? :streams

      @db.create_table :descs do
        primary_key :id
        column :desc, :string
      end unless @db.table_exists? :descs

      @db.create_table :exception_types do
        primary_key :id
        column :exception_type, :string
      end unless @db.table_exists? :exception_types

      @db.create_table :exception_subtypes do
        primary_key :id
        column :exception_subtype, :string
      end unless @db.table_exists? :exception_subtypes

      @db.create_table :classifications do
        primary_key :id
        column :classification, :string
      end unless @db.table_exists? :classifications

      @db.create_table :result_strings do
        primary_key :id
        column :result_string, :string
      end unless @db.table_exists? :result_strings
    end

    def add_unless_seen( table_sym, string )
      # Set all this up in advance...
      unless @db[table_sym][(table_sym.to_s[0..-2].to_sym)=>string]
        @db[table_sym].insert((table_sym.to_s[0..-2].to_sym)=>string)
      end
    end

    def id_for_string( table_sym, string )
      #Try the hash first
      @db[table_sym][(table_sym.to_s[0..-2].to_sym)=>string][:id]
    end

    # Add a new result, return the db_id
    def add_result(status, crashdetail=nil, crashfile=nil, template=nil, encoding='base64')
      # WRAP ALL THIS IN A TRANSACTION
      begin
        @db.transaction do
          db_id=@db[:results].insert(:result_id=>id_for_string(:result_strings, status))
          if status='crash'

            frames=DetailParser.stack_trace crashdetail
            add_stacktrace(db_id, frames)

            registers=DetailParser.registers crashdetail
            add_registers(db_id, registers)

            disassembly=DetailParser.disassembly crashdetail
            add_disassembly(db_id, disassembly)
          end
        end
      rescue
        raise
      end
      db_id
    end

    def add_disassembly(crash_id, disasm)
      disassemly.each {|seq, instruction|
        address, asm=instruction.split(' ',2)
        @db[:disasm].insert(
          :crash_id=>crash_id,
          :seq=>seq,
          :address=>address,
          :asm=>asm
        )
      }
    end

    def add_registers(crash_id, registers) 
      register_hash={}
      registers.each {|r,v| register_hash[r.to_sym]=v.to_i(16)}
      register_hash[:crash_id]=crash_id
      @db[:register_dumps].insert register_hash
    end

    def add_stacktrace(crash_id, stackframes)
      stacktrace = @db[:stacktraces].insert(:crash_id => crash_id)

      frames.each do |f|
        sequence = f[0]
        func_data = f[1]
        library, func_data = func_data.split('!')
        function, address = func_data.split('+')

        @db[:stackframes].insert(:stacktrace_id => stacktrace,
                                 :function_id => resolve(library, func),
                                 :address => address,
                                 :sequence => sequence)
      end
    end

    def resolve(library, function)
      module_id = @db[:modules][:name => library]
      @db[:functions][:module_id => module_id][:name => function]
    end

    def add_module(name, path, version)
      @db[:modules].insert(:name => name,
                           :path => path,
                           :version => version)
    end

    def add_function(library, name, address)
      @db[:functions].insert(:name => name,
                             :module_id => id_for_string(library),
                             :address => address)
    end

    def get_stacktrace(crash_id)
      trace_id = @db[:stacktraces][:crash_id => crash_id]
      @db[:stackframes].filter(:stacktrace_id => trace_id).order(:sequence).all()
    end

    # In: database unique crash_id as an int
    # Out: the result string, 'success', 'crash' or 'fail'
    def result( id )
    end

    # In: database unique crash_id as an int
    # Out: the crashfile, base64 encoded by default
    def crashfile( id, encoding='base64' )
    end

    # In: database unique crash_id as an int
    # Out: the raw detail file (cdb output)
    def crashdetail( id )
    end

    # In: database unique crash_id as an int
    # Out: Registers at crash time, as a hash {'eax'=>'0x00000000' etc
    def registers( id )
    end

    # In: database unique crash_id as an int
    # Out: The stack trace as an array of strings sorted top to bottom
    def stack_trace( id )
    end

    # In: database unique crash_id as an int
    # Out: Exception subtype as a string
    def exception_subtype( id )
    end

    # In: database unique crash_id as an int
    # Out: Exception short description as a string
    def exception_short_desc( id )
    end

    # In: database unique crash_id as an int
    # Out: Exception long description as a string
    def exception_long_desc( id )
    end

    # In: Major hash as provided by !exploitable as a string
    # Out: Array of crash ids as ints
    def crashes_by_major_hash( hash_string )
    end

    # In: Full hash as provided by !exploitable as a string
    # Out: Array of crash ids as ints
    def crashes_by_hash( hash_string )
    end

    # Run an SQL query string against the database
    def execute_raw_sql( sql_string )
    end

    def method_missing( meth, *args )
      @db.send meth, *args
    end
  end

  class TraceDB
  end

end
