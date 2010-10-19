require File.dirname(__FILE__) + '/../core/connector'
require File.dirname(__FILE__) + '/conn_office'
require File.dirname(__FILE__) + '/conn_cdb'
require File.dirname(__FILE__) + '/drb_debug_client'
require 'rubygems'
require 'trollop'
require 'drb'
require 'open3'

OPTS=Trollop::options do
    opt :port, "Port to listen on, default 8888", :type=>:integer, :default=>8888
    opt :debug, "Debug mode", :type=>:boolean
end

class Monitor

    COMPONENT="Monitor"
    VERSION="1.1.0"
    MONITOR_DEFAULTS={
        'timeout'=>30,
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
        warn "#{COMPONENT}:#{VERSION}: Spawning debug server on #{OPTS[:port]+1}..." if OPTS[:debug]
        system("start cmd /k ruby drb_debug_server.rb -p #{OPTS[:port]+1} #{OPTS[:debug]? ' -d' : ''}")
        @debug_client=DebugClient.new('127.0.0.1', OPTS[:port]+1)
    rescue
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        raise $!
    end

    def start_debugger( pid )
        @debugger_uri=@debug_client.start_debugger('pid'=>pid, 'options'=>"-xi ld -snul", 'path'=>CDB_PATH )
        @debugger=DRbObject.new nil, @debugger_uri
        @debugger.puts "!load winext\\msec.dll"
        #@debugger.puts ".sympath c:\\localsymbols"
        @debugger.puts "sxe -c \".echo frobozz;r;~;kv;u @eip;!exploitable -m;.echo xyzzy\" av"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy\" sbo"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy\" ii"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy\" gp"
        @debugger.puts "sxi e0000001"
        @debugger.puts "sxi e0000002"
        @debugger.sync
        @debugger.dq_all
        @debugger.puts "g"
        warn "#{COMPONENT}:#{VERSION}: Attached debugger to pid #{pid}" if OPTS[:debug]
    rescue Exception=> e
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        warn e.backtrace
        raise "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} "
    end

    def start_dk_thread( app_wid )
        warn "#{COMPONENT}:#{VERSION}: Starting DK thread against wid #{app_wid}" if OPTS[:debug]
        @dk_thread.kill if @dk_thread
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
                    sleep(0.5)
                    print 'o'
                rescue
                    sleep(0.5)
                    warn "#{COMPONENT}:#{VERSION}: Error in DK thread: #{$!}"
                    retry
                end
            end
        end
    end

    def check_for_timeout
        if Time.now - @mark > @monitor_args['timeout']
            warn "#{COMPONENT}:#{VERSION}: Timeout (#{Time.now - @mark}) Exceeded." if OPTS[:debug]
            @hang=true
            @debugger.sync
            if fatal_exception?( debugger_output=@debugger.dq_all )
                warn "#{COMPONENT}:#{VERSION}: Fatal exception after hang" if OPTS[:debug]
                treat_as_fatal( debugger_output )
            else
                warn "#{COMPONENT}:#{VERSION}: No exception after hang" if OPTS[:debug]
                reset
            end
        end
    rescue
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        raise $!
    end

    def treat_as_fatal( debugger_output )
        get_minidump if @monitor_args['minidump']
        @exception_data=debugger_output
        reset
    rescue
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        raise $!
    end

    def start_monitor_thread( pid )
        raise RuntimeError, "#{COMPONENT}:#{VERSION}: Debugger not initialized yet!" unless @debugger
        @monitor_thread.kill if @monitor_thread
        @monitor_thread=Thread.new do
            @mark=Time.now
            @running=true
            @hang=false
            loop do
                begin
                    @pid=pid
                    sleep 1
                    raise RuntimeError, "PID Mismatch" unless @pid==@debugger.target_pid
                    if @debugger.target_running?
                        check_for_timeout
                    else
                        @debugger.sync
                        debugger_output=@debugger.dq_all
                        warn "#{COMPONENT}:#{VERSION}: Target #{@debugger.target_pid} broken..." if OPTS[:debug]
                        if fatal_exception? debugger_output
                            warn "#{COMPONENT}:#{VERSION}: Fatal exception. Killing debugee." if OPTS[:debug]
                            treat_as_fatal( debugger_output )
                        else
                            warn "#{COMPONENT}:#{VERSION}: Broken, but no fatal exception. Ignoring." if OPTS[:debug]
                            warn debugger_output if OPTS[:debug]
                            @debugger.puts "g" 
                            sleep 0.1
                        end
                    end
                rescue
                    @running=false
                    warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} Set running to false " if OPTS[:debug]
                    reset
                end
            end
        end
    rescue
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        @running=false
        raise $!
    end

    def running?
        @running
    end

    def hang?
        @hang
    end

    def get_minidump
        warn "#{COMPONENT}:#{VERSION}: Collecting minidump..." if OPTS[:debug]
        #do something
    end

    def fatal_exception?( output )
        # Do any of the exceptions match none of the ignore regexps?
        unless output.scan(/frobozz/).length==output.scan(/xyzzy/).length
            raise RuntimeError, "#{COMPONENT}:#{VERSION}:#{__method__}: unfinished exception output."
        end
        output=~/second chance/i or output.scan( /frobozz(.*?)xyzzy/m ).any? {|exception|
            @monitor_args['ignore_exceptions'].none? {|ignore_regexp| ignore_regexp.match exception} 
        }
    rescue
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        raise $!
    end

    def start( app_pid, app_wid, arg_hsh={} )
        warn "#{COMPONENT}:#{VERSION}: Starting to monitor pid #{app_pid}" if OPTS[:debug]
        reset
        start_debugger( app_pid )
        raise RuntimeError, "#{COMPONENT}:#{VERSION}: Debugee PID mismatch" unless @debugger.target_pid==app_pid
        @monitor_args=MONITOR_DEFAULTS.merge( arg_hsh )
        start_dk_thread( app_wid ) if @monitor_args['kill_dialogs']
        start_monitor_thread( app_pid )
    rescue
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        raise $!
    end

    def reset
        warn "#{COMPONENT}:#{VERSION}: Reset called, debugger #{@debugger.target_pid rescue 0}." if OPTS[:debug]
        @debug_client.close_debugger if @debugger
        @debugger=nil
        @monitor_thread.kill if @monitor_thread
        @dk_thread.kill if @dk_thread
        @monitor_thread=@dk_thread=@exception_data=@running=nil
        warn "#{COMPONENT}:#{VERSION}: Reset." if OPTS[:debug]
    rescue
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        raise $!
    end

    def new_test
        warn "#{COMPONENT}:#{VERSION}: Prepping for new test" if OPTS[:debug]
        @mark=Time.now 
        @debugger.dq_all
        @exception_data=nil
    rescue
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        raise $!
    end

    def destroy
        warn "#{COMPONENT}:#{VERSION}: Destroying." if OPTS[:debug]
        @debug_client.destroy_server
        DRb.thread.kill
    rescue
        warn "#{COMPONENT}:#{VERSION}: #{__method__} #{$!} " if OPTS[:debug]
        raise $!
    end

end

DRb.start_service( "druby://127.0.0.1:#{OPTS[:port]}", Monitor.new )
DRb.thread.join
