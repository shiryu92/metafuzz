require './debug_client'
require 'open3'

puts "Connecting"
dc=DebugClient.new '127.0.0.1', 9000
mark=Time.now
loop do
   Open3.popen3('notepad.exe') {|i,o,e,thr|
        puts "Starting Debugger"
        dc.start_debugger('pid'=>thr[:pid], 'path'=>'"C:\\Program Files\\Debugging Tools for Windows (x86)\\cdb.exe" ', 'options'=>'-xi ld -snul')
        puts "OK Debugger is pid #{dc.debugger_pid}, Target pid #{dc.target_pid}..."
        puts "Sending u @eip"
        dc.puts "u @eip"
        puts dc.dq_all
        puts "Getting Registers"
        puts dc.registers
        puts "Starting"
        dc.puts "g"
        puts "Getting Registers again"
        puts dc.registers
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
        dc.close_debugger
    }
end
puts Time.now - mark

