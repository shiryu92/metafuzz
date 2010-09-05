require './drb_debug_client'
require 'open3'

puts "Connecting"
dc=DebugClient.new '127.0.0.1', 9000
mark=Time.now
loop do
    Open3.popen3('notepad.exe') {|i,o,e,thr|
        puts "Starting Debugger"
        uri=dc.start_debugger('pid'=>thr[:pid], 'path'=>'"C:\\Program Files\\Debugging Tools for Windows (x86)\\cdb.exe" ', 'options'=>'-xi ld -snul')
        primary_debugger=DRbObject.new nil, uri
        secondary_debugger=DRbObject.new nil, uri
        puts "OK Debugger is pid #{primary_debugger.debugger_pid}, Target pid #{primary_debugger.target_pid}..."
        puts "Sending u @eip"
        primary_debugger.puts "u @eip"
        puts secondary_debugger.dq_all
        puts "Getting Registers"
        puts primary_debugger.registers
        puts "Starting"
        primary_debugger.puts "g"
        puts "Getting Registers from Secondary"
        puts secondary_debugger.registers
        puts "Starting"
        primary_debugger.puts "g"
        puts "Stopping"
        secondary_debugger.send_break
        puts "Getting old output"
        puts "SECONDARY SAYS"
        puts secondary_debugger.qc_all
        puts "PRIMARY SAYS"
        puts primary_debugger.dq_all
        puts "Disasm esp"
        primary_debugger.puts "u @esp"
        puts secondary_debugger.dq_all
        puts "Killing it"
        primary_debugger.puts ".kill"
        primary_debugger.puts "g"
        puts primary_debugger.dq_all
        dc.close_debugger
    }
end
puts Time.now - mark
