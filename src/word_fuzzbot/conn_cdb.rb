require File.dirname(__FILE__) + '/windows_popen'
require 'win32api'
require File.dirname(__FILE__) + '/../core/objhax'
require 'win32/process'
require 'win32ole'
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
    COMPONENT="CONN_CDB"
    VERSION="3.6.0"
    include Windows::Thread
    include Windows::Handle
    include Windows::Error
    include Windows::ToolHelper
    GenerateConsoleCtrlEvent=Win32API.new("kernel32", "GenerateConsoleCtrlEvent", ['I','I'], 'I')

    def raise_win32_error 
        unless (error_code=GetLastError.call) == ERROR_SUCCESS 
            msg = ' ' * 255 
            FormatMessage.call(0x3000, 0, error_code, 0, msg, 255, '') 
            raise "#{COMPONENT}:#{VERSION}: Win32 Exception: #{msg.gsub!(/\000/, '').strip!}" 
        else 
            raise 'GetLastError returned ERROR_SUCCESS' 
        end 
    end

    def establish_connection
        arg_hash=@module_args[0]
        raise ArgumentError, "CONN_CDB: No Pid to attach to!" unless arg_hash['pid']
        @target_pid=arg_hash['pid']
        begin
            @cdb_app=WindowsPipe.popen( (arg_hash['path'] || CDB_PATH)+"-p #{arg_hash['pid']} "+"#{arg_hash['options']}" )
        rescue Exception=>e
            $stdout.puts $!
            $stdout.puts e.backtrace
        end

    end

    # Return the pid of the debugger
    def debugger_pid
        if @cdb_app
            @cdb_app.pid
        else
            -1
        end
    end

    def target_pid
        @target_pid||=false
        @target_pid
    end

    #Blocking read from the socket.
    def blocking_read
        @cdb_app.read
    end

    #Blocking write to the socket.
    def blocking_write( data )
        @cdb_app.write data
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
            @cdb_app.close if @cdb_app
            @cdb_app=nil # for if destroy_connection gets called twice
        rescue Exception=>e
            $stdout.puts $!
            $stdout.puts e.backtrace
            raise $!
        end
    end

    # Sugar from here on.

    #Our popen object isn't actually an IO obj, so it only has read and write.
    def puts( str )
        blocking_write "#{str}\n"
    end

    def send_break
        # 1 -> Ctrl-Break event
        GenerateConsoleCtrlEvent.call( 1, @cdb_app.pid )
        sleep(0.1)
    end

    def sync
        # This is awful.
        send_break if target_running?
        puts ".echo #{cookie=rand(2**32)}"
        mark=Time.now
        until qc_all =~ /#{cookie}/
            sleep 1
            raise "#{COMPONENT}:#{VERSION}:#{__method__}: #{$!}" if Time.now - mark > 3
        end
    end

    def target_running?
        begin
            raise_win32_error if (snap=CreateToolhelp32Snapshot.call( TH32CS_SNAPTHREAD, 0 ))==INVALID_HANDLE_VALUE
            # I'm going to go ahead and do this the horrible way. This is a
            # blank Threadentry32 structure, with the size (28) as the first
            # 4 bytes (little endian). It will be filled in by the Thread32Next
            # calls
            thr_raw="\x1c" << "\x00"*27
            raise_win32_error unless Thread32First.call(snap, thr_raw)==1
            while Thread32Next.call(snap, thr_raw)==1
                # Again, manually 'parsing' the structure in hideous fashion
                owner=thr_raw[12..15].unpack('L').first
                tid=thr_raw[8..11].unpack('L').first
                if owner==target_pid
                    begin
                        raise_win32_error if (hThread=OpenThread.call( THREAD_ALL_ACCESS,0,tid )).zero?
                        raise_win32_error if (suspend_count=SuspendThread.call( hThread ))==INVALID_HANDLE_VALUE
                        raise_win32_error if (ResumeThread.call( hThread ))==INVALID_HANDLE_VALUE
                    ensure
                        CloseHandle.call( hThread )
                    end
                    return true if suspend_count==0
                end
            end
            return false
        ensure
            CloseHandle.call( snap )
        end
    end

    def registers
        send_break if target_running?
        puts 'r'
        sync 
        mark=Time.now
        until (regstring=qc_all) =~ /eax.*?efl=.*$/m
            raise "#{COMPONENT}:#{VERSION}:#{__method__}: #{$!}" if Time.now - mark > 5
        end
        Hash[*(regstring.scan(/eax.*?efl=.*$/m).last.scan(/ (\w+?)=([0-9a-f]+)/)).flatten]
    rescue
        $stderr.puts "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} "
        raise $!
    end

end # module CONN_CDB

