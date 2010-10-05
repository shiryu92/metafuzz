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
module CONN_CDB

CDB_PATH="\"C:\\WinDDK\\Debuggers\\cdb.exe\" "

    #Set up a new socket.
    def establish_connection
        arg_hash=@module_args[0]
        raise ArgumentError, "CONN_CDB: No Pid to attach to!" unless arg_hash['pid']
        @generate_ctrl_event||= Win32API.new("kernel32", "GenerateConsoleCtrlEvent", ['I','I'], 'I')
        @target_pid=arg_hash['pid']
        begin
            @stdin,@stdout,@stderr,@thr=Open3.popen3( (arg_hash['path'] || CDB_PATH)+"-p #{arg_hash['pid']} "+"#{arg_hash['options']}" )
            @cdb_pid=@thr[:pid]
            sleep 0.1
        rescue Exception=>e
            $stdout.puts $!
            $stdout.puts e.backtrace
        end

    end

    # Return the pid of the debugger
    def debugger_pid
        @cdb_pid||=false
        @cdb_pid
    end

    def target_pid
        @target_pid||=false
        @target_pid
    end

    #Blocking read from the socket.
    def blocking_read
        @stdout.read(1)
    end

    #Blocking write to the socket.
    def blocking_write( data )
        @stdin.write data
        sleep(0.1)
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
            @thr || return
            @stdin.close
            @stdout.close
            @stderr.close
            #kill the CDB process
            @thr.kill
        rescue Exception=>e
            $stdout.puts $!
            $stdout.puts e.backtrace
            nil
        end
    end

    # Sugar from here on.

    #Our popen object isn't actually an IO obj, so it only has read and write.
    def puts( str )
        blocking_write "#{str}\n"
    end

    def send_break
        # This sends a ctrl-break to every process in the group!
        # You can ignore it in the parent (ruby) process with
        # trap(21) {nil} or similar.
        @generate_ctrl_event.call(1,0)
        sleep(0.15)
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
    # Overall, this is not a rock-solid method. For industrial strength, better
    # to never clear the queue and just parse everything
    def registers
        send_break
        puts 'r'
        regstring=''
        # Potential infinite loop here :(
        counter=0
        until (regstring << dq_all) =~ /eax.*efl=/m
            sleep 0.1
            if counter >= 20
                $stdout.puts "Reconnecting"
                reconnect
                sleep 1
            end
            counter+=1
        end
        Hash[*(regstring.scan(/^eax.*?iopl/m).last.scan(/(e..)=([0-9a-f]+)/)).flatten]
    end

end # module CONN_CDB

