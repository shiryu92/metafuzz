require 'debug_client'
require 'open3'
require '../core/connector'
require 'conn_cdb'

puts "Connecting"
sleep 60
trap(21) {nil}
loop do
        ps,pi,pe,thr=Open3.popen3('notepad.exe')
        puts "Starting Debugger"

        dc=Connector.new( CONN_CDB, 'pid'=>thr[:pid], 'path'=>'"C:\\Program Files\\Debugging Tools for Windows (x86)\\cdb.exe" ', 'options'=>'-xi ld -snul')
        puts "OK Debugger is pid #{dc.debugger_pid}, Target pid #{dc.target_pid}..."
        puts "Getting Registers"
        puts dc.registers
        puts "Starting"
        dc.puts "g"
        puts "Getting Registers again"
        puts dc.registers
        puts "Sending u @eip"
        dc.puts "u @eip"
        puts "Starting"
        dc.puts "g"
        puts "Stopping"
        dc.send_break
        puts "Getting old output"
        puts dc.dq_all
        puts "Disasm esp"
        dc.puts "u @esp"
        puts dc.dq_all
        puts "Killing it"
        dc.puts ".kill"
        dc.puts "g"
        puts dc.dq_all
        dc.close
        ps.close
        pi.close
        pe.close
        GC.start
end

