require File.dirname(__FILE__) + '/../core/connector'
require File.dirname(__FILE__) + '/conn_office'
require File.dirname(__FILE__) + '/conn_cdb'
require 'rubygems'
require 'trollop'
require 'drb'

OPTS=Trollop::options do
    opt :port, "Port to listen on, default 8888", :type=>:integer, :default=>8888
    opt :debug, "Debug mode", :type=>:boolean
end

class Monitor

    COMPONENT="Monitor"
    VERSION="1.1.0"
    MONITOR_DEFAULTS={
        'timeout'=>15,
        'ignore_exceptions'=>[],
        'kill_dialogs'=>true
    }
    CDB_PATH='"C:\\Program Files\\Debugging Tools for Windows (x86)\\cdb.exe" '

    # Constants for the dialog killer thread
    BMCLICK=0x00F5
    WM_DESTROY=0x0010
    WM_COMMAND=0x111
    IDOK=1
    IDCANCEL=2
    IDNO=7
    IDCLOSE=8
    GW_ENABLEDPOPUP=0x0006
    # Win32 API definitions for the dialog killer
    FindWindow=Win32API.new("user32.dll", "FindWindow", 'PP','N')
    GetWindow=Win32API.new("user32.dll", "GetWindow", 'LI','I')
    PostMessage=Win32API.new("user32.dll", "PostMessage", 'LILL','I')

    attr_reader :exception_data

    def initialize
        system("start cmd /k ruby debug_server.rb -p 8888")
        @debug_client=DebugClient.new('127.0.0.1', 8888)
    end

    def start_debugger( pid )
        @debugger_uri=@debug_client.start_debugger('pid'=>pid, 'options'=>"-xi ld", 'path'=>CDB_PATH )
        @debugger=DRbObject.new nil, @debugger_uri
        @debugger.puts "!load winext\\msec.dll"
        @debugger.puts ".sympath c:\\localsymbols"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy\" av"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy\" sbo"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy\" ii"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy\" gp"
        @debugger.puts "sxi e0000001"
        @debugger.puts "sxi e0000002"
        @debugger.puts "g"
        warn "#{COMPONENT}:#{VERSION}: Attached debugger to pid #{pid}" if OPTS[:debug]
    end

    def start_dk_thread( app_wid )
        @dk_thread=Thread.new do
            loop do
                begin
                    # Get any descendant windows which are enabled - alerts, dialog boxes etc
                    child_hwnd=GetWindow.call(app_wid, GW_ENABLEDPOPUP)
                    unless child_hwnd==0
                        PostMessage.call(child_hwnd,WM_COMMAND,IDCANCEL,0)
                        PostMessage.call(child_hwnd,WM_COMMAND,IDNO,0)
                        PostMessage.call(child_hwnd,WM_COMMAND,IDCLOSE,0)
                        PostMessage.call(child_hwnd,WM_COMMAND,IDOK,0)
                        PostMessage.call(child_hwnd,WM_DESTROY,0,0)
                    end
                    # conn_office.rb changes the caption, so this should only detect toplevel dialog boxes
                    # that pop up during open before the main Word window.
                    toplevel_box=FindWindow.call(0, "Microsoft Office Word")
                    unless toplevel_box==0
                        PostMessage.call(toplevel_box,WM_COMMAND,IDCANCEL,0)
                        PostMessage.call(toplevel_box,WM_COMMAND,IDNO,0)
                        PostMessage.call(toplevel_box,WM_COMMAND,IDCLOSE,0)
                        PostMessage.call(toplevel_box,WM_COMMAND,IDOK,0)
                    end
                    sleep 0.1
                rescue
                    sleep 0.1
                    warn "#{COMPONENT}:#{VERSION}: Error in DK thread: #{$!}"
                    retry
                end
            end
        end
    end

    def start_monitor_thread( timeout )
        raise RuntimeError, "#{COMPONENT}:#{VERSION}: Debugger not initialized yet!" unless @debugger
        @monitor_thread=Thread.new do
            check_count=0
            loop do
                if @debugger.target_running?
                    sleep 0.1
                    check_count+=1
                    if check_count > timeout*10
                        warn "#{COMPONENT}:#{VERSION}: Timeout (check count #{check_count}). Breaking." if OPTS[:debug]
                        @debugger.send_break
                    end
                else
                    debugger_output=@debugger.qc_all
                    if fatal_exception? debugger_output
                        warn "#{COMPONENT}:#{VERSION}: Fatal exception. Killing debugee." if OPTS[:debug]
                        get_minidump if @monitor_args['minidump']
                        @debugger.puts ".kill"
                        @debugger.puts "g"
                        @exception_data=debugger_output
                    else
                        warn "#{COMPONENT}:#{VERSION}: Broken, but no fatal exception. Ignoring." if OPTS[:debug]
                        @debugger.puts "g"
                    end

                end
            end
        end
    end

    def get_minidump
        warn "#{COMPONENT}:#{VERSION}: Collecting minidump..." if OPTS[:debug]
        #do something
    end

    def fatal_exception?( output )
        # Do any of the exceptions match none of the ignore regexps?
        @debugger.qc_all.scan( /frobozz(.*?)xyzzy/m ).any? {|exception|
            @monitor_args['ignore_exceptions'].none? {|ignore_regexp| ignore_regexp.match exception} 
        }
    end

    def start_monitoring( app_pid, app_wid, arg_hsh={} )
        warn "#{COMPONENT}:#{VERSION}: Starting to monitor pid #{app_pid}" if OPTS[:debug]
        unless @debugger
            start_debugger( app_pid )
        else
            raise RuntimeError, "#{COMPONENT}:#{VERSION}: Debugee PID mismatch" unless @debugger.target_pid==app_pid
        end
        @monitor_args=MONITOR_DEFAULTS.merge( arg_hsh )
        start_monitor_thread( arg_hsh['timeout'] )
        start_dk_thread( app_wid ) if arg_hsh['kill_dialogs']
    end

    def stop_monitoring( *args )
        warn "#{COMPONENT}:#{VERSION}: Stopping monitoring #{@debugger.target_pid}." if OPTS[:debug]
        @monitor_thread.kill if @monitor_thread
        @dk_thread.kill if @dk_thread
        @monitor_thread=@dk_thread=@exception_data=nil
    end

    def reset
        stop_monitoring
        @debugger_client.close_debugger
        @debugger=nil
        warn "#{COMPONENT}:#{VERSION}: Reset." if OPTS[:debug]
    end

end

trap(21) {
    # CTRL_BREAK - Ignore
}

DRb.start_service( "druby://127.0.0.1:#{OPTS[:port]}", Monitor.new )
DRb.thread.join
