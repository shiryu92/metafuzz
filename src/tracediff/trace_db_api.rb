require File.dirname(__FILE__) + '/trace_db_schema'
require 'rubygems'
require 'sequel'
require 'pg'

# Just a quick wrapper, so I can change the underlying DB.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
module MetafuzzDB

    class TraceDB

        def initialize(url, username, password, max_buffer=70000)
            @db=Sequel::connect(url, :username=>username, :password=>password)
            TraceDBSchema.setup_schema( @db )
            @buffer=[]
            @max_buffer=max_buffer
        end

        # Inserts the string to the given table if it's not there
        # already, and returns the id
        def id_for_string( table_sym, string )
            @db[table_sym][(table_sym.to_s[0..-2].to_sym)=>string][:id]
        rescue
            @db[table_sym].insert((table_sym.to_s[0..-2].to_sym)=>string)
        end

        def transition_type_id( type_str )
            @transition_type_cache||={}
            if id=@transition_type_cache[type_str]
                # yay
            else
                id=id_for_string( :transition_types, type_str)
                @transition_type_cache[type_str]=id
            end
            id
        end

        def new_trace( filename )
            @db[:traces].insert(:filename=>filename, :timestamp=>Time.now)
        end

        def append_entry( trace_id, entry_hsh )
            this_line={
                :trace_id=>trace_id,
                :transition_type=>(transition_type_id(entry_hsh["type"])),
                :from=>entry_hsh["from"],
                :to=>entry_hsh["to"],
                :eax=>entry_hsh["state"]["eax"],
                :ebx=>entry_hsh["state"]["ebx"],
                :ecx=>entry_hsh["state"]["ecx"],
                :edx=>entry_hsh["state"]["edx"],
                :esp=>entry_hsh["state"]["esp"],
                :ebp=>entry_hsh["state"]["ebp"],
                :esi=>entry_hsh["state"]["esi"],
                :edi=>entry_hsh["state"]["edi"],
                :flags=>entry_hsh["state"]["flags"]
            }
            @buffer << this_line
            if @buffer.size >= @max_buffer
                @db[:trace_lines].multi_insert @buffer
                @buffer.clear
            end
        end

        def flush
            unless @buffer.empty?
                @db[:trace_lines].multi_insert @buffer
            end
        end

        def add_module( trace_id, module_hsh )
            begin
                mod_id=@db[:modules][:checksum=>module_hsh["checksum"]][:id]
            rescue
                mod_id=@db[:modules].insert(
                    :name=>module_hsh["name"], 
                    :size=>module_hsh["size"], 
                    :checksum=>module_hsh["checksum"]
                )
            end
            @db[:loaded_modules].insert(
                :trace_id=>trace_id,
                :module_id=>mod_id,
                :base=>module_hsh["base"]
            )

        end

        def method_missing( meth, *args )
            @db.send meth, *args
        end
    end

end
