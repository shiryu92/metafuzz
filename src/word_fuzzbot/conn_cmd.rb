require File.dirname(__FILE__) + '/windows_popen'
require 'win32api'
require File.dirname(__FILE__) + '/../core/objhax'
require 'win32/process'
require 'open3'

#Establish a connection to the Windows CDB debugger. CDB has all the features of WinDbg, but it uses
#a simple command line interface.
#
#Parameters: For now, the full command line EXCLUDING the path to cdb itself as a string. 
#Sugar may follow later. Remember that program names that include spaces need to be 
#enclosed in quotes \"c:\\Program Files [...] \" etc.
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
module CONN_CMD


    #Set up a new socket.
    def establish_connection
        @generate_ctrl_event = Win32API.new("kernel32", "GenerateConsoleCtrlEvent", ['I','I'], 'I')
        begin
            @stdin,@stdout,@stderr,@thr=Open3::popen3("cmd")
            @pid=@thr[:pid]
            $stdout.sync=true
        rescue
            #do something
        end

    end

    #Blocking read from the socket.
    def blocking_read
        @stdout.read(1)
    end

    #Blocking write to the socket.
    def blocking_write( data )
        @stdin.write data
    end

    #Return a boolen.
    def is_connected?
        # The process is alive - is that the same as connected?
        # TODO: I don't think this method works...
        Process.kill(0,@cdb_pid).include?(@cdb_pid)
    end

    #Cleanly destroy the socket. 
    def destroy_connection
        begin
            #kill the CDB process
            @stdin.close
            @stdout.close
            @stderr.close
            Process.kill( 9, @pid )
        rescue
            nil
        end
    end

    # Sugar from here on.

    #Our popen object isn't actually an IO obj, so it only has read and write.
    def puts( str )
        @stdin.write "#{str}\n"
    end

    def send_break
        @generate_ctrl_event.call(1,@cdb_pid)
        sleep(1)
        true
    end

    def target_running?
        state=qc_all.join
        return false if state[-1]==" "
        true
    end

    # Deprecated
    def crash?
        qc_all.join=~/second chance/
    end

    # Because this method is a point in time capture of the registers we flush
    # the queue.
    def registers
        send_break if target_running?
        puts  "r" # puts to the debugger, not stdout
        regstring=''
        # Potential infinite loop here :(
        sleep 0.1 until (regstring << dq_all.join).index('efl=')
        regstring=regstring[regstring.index('eax=')..-1].gsub!("\n",' ') 
        reghash={}
        regstring.split(' ').each {|tok|
            if tok.split('=').length==2
                reghash[tok.split('=')[0].to_sym]=tok.split('=')[1]
            end
        }
        reghash
    end

end # module CONN_CDB

