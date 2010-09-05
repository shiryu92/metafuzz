require File.dirname(__FILE__) + '/../core/connector'
require File.dirname(__FILE__) + '/conn_office'
require File.dirname(__FILE__) + '/conn_cdb'
require File.dirname(__FILE__) + '/debug_client'
require File.dirname(__FILE__) + '/monitor_client'
require 'rubygems'
require 'msgpack/rpc'

class WordDeliveryAgent

    CDB_PATH='"C:\\Program Files\\Debugging Tools for Windows (x86)\\cdb.exe" '

    def initialize( arg_hash )
        @args=arg_hash
        # Attach debugger
        system("start ruby debug_server.rb -p 8888")
        system("start ruby dialog_killer.rb")
        system("start /HIGH ruby monitor_server.rb -p 8889") # Better chance of killing memory hogs
        @debug_client=DebugClient.new('127.0.0.1', 8888)
        @monitor_client=MonitorClient.new('127.0.0.1', 8889)
        start_clean_word
    end

    def start_clean_word
        @word_conn.close
        begin
            5.times do
                begin
                    @word_conn=Connector.new(CONN_OFFICE, 'word')
                    break
                rescue
                    warn "Word wrapper: Failed to create connection: #{$!}" if @args[:debug]
                    sleep(1)
                    next
                end
            end
            @current_pid=@word_conn.pid
        rescue
            raise RuntimeError, "Couldn't establish connection to app. #{$!}"
        end
        @word_conn.set_visible if @args[:visible]
        start_debugger
    end

    def start_debugger
        @debug_client.start_debugger(@current_pid, "-xi ld", CDB_PATH )
        @debug_client.puts "!load winext\\msec.dll"
        @debug_client.puts ".sympath c:\\localsymbols"
        @debug_client.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy;\" av"
        @debug_client.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy;\" sbo"
        @debug_client.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy;\" ii"
        @debug_client.puts "sxe -c \".echo frobozz;r;!exploitable -m;.echo xyzzy;\" gp"
        @debug_client.puts "sxi e0000001"
        @debug_client.puts "sxi e0000002"
        @debug_client.puts "g"
    end

    def deliver( filename, delivery_options )
        status='error'
        crash_details=''
        dump=''
        if delivery_options.include?( "clean") or not @word_conn.connected?
            start_clean_word
        end
        @monitor_client.start_monitoring( @current_pid, delivery_options )
        begin
            warn "Filename: #{filename}" if @debug
            @word_conn.blocking_write( filename, repair )
            # As soon as the deliver method doesn't raise an exception, we lose interest.
            @monitor_client.stop_monitoring
            status='success'
        rescue Exception=>e
            @monitor_client.stop_monitoring
            if @monitor_client.crash_found?
                status='crash'
                crash_details, dump=@monitor_client.crash_details
                start_clean_word
            else
                status='fail'
                # Word stays open, dirty.
            end
        end
        [status,crash_details,dump]
    end

    def destroy
        @word_conn.close
        @debug_client.close_debugger
    end

    def method_missing( meth, *args )
        warn "MM: #{meth}" if @args[:debug]
        @word_conn.send( meth, *args )
    end

end

