#require File.dirname(__FILE__) + '/rtdbwrapper'

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
        end

        # Add a new result, return the db_id
        def add_result(id, status, crashdetail=nil, crashfile=nil, template=nil, encoding='base64')
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
