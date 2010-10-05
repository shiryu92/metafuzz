require File.dirname(__FILE__) + '/../core/connector'
require File.dirname(__FILE__) + '/conn_office'
require File.dirname(__FILE__) + '/conn_cdb'
require File.dirname(__FILE__) + '/debug_client'
require File.dirname(__FILE__) + '/monitor'
require 'rubygems'
require 'msgpack/rpc'

class WordDeliveryAgent


    COMPONENT="WordDeliveryAgent"
    VERSION="1.1.0"
    DELIVERY_DEFAULTS={
        'clean'=>false, 
        'norepair'=>false, 
        'minidump'=>false, 
        'filechain'=>false,
        'maxchain'=>20,
        'ignore_exceptions'=>[]
    }

    AGENT_DEFAULTS={
        'debug'=>false,
        'visible'=>true
    }

    def initialize( arg_hash={} )
        @agent_options=AGENT_DEFAULTS.merge( arg_hash )
        # Start with high priority for better chance of killing processes pegging the CPU
        @mi,@mo,@me,@mt=Open3::popen3("start /HIGH cmd /k ruby monitor_server.rb #{@agent_options['debug']? '-d' : ' ' }-p 8889")
        @monitor=DRbObject.new(nil, "druby://127.0.0.1:8889")
        @current_chain=[]
        start_clean_word
    end

    def start_clean_word
        @word_conn.close if @word_conn
        begin
            5.times do
                begin
                    @word_conn=Connector.new(CONN_OFFICE, 'word')
                    break
                rescue
                    warn "Word wrapper: Failed to create connection: #{$!}" if @agent_options[:debug]
                    sleep(1)
                end
            end
            @current_pid=@word_conn.pid
        rescue
            raise RuntimeError, "Couldn't establish connection to app. #{$!}"
        end
        @word_conn.set_visible if @agent_options['visible']
        @current_chain.clear
    end

    def deliver( filename, delivery_options={} )
        status='error'
        exception_data=''
        dump='' # not implemented yet
        chain=''
        delivery_options=DELIVERY_DEFAULTS.merge( delivery_options )
        if delivery_options['clean'] or not @word_conn.connected? or @current_chain.size >= delivery_options['maxchain']
            start_clean_word
            @monitor.reset
        end
        @monitor.start_monitoring( @word_conn.pid, @word_conn.wid, delivery_options )
        begin
            warn "Filename: #{filename}" if @agent_options['debug']
            # Always keep file chains, but only send them back
            # when the filechain option is set. Uses more RAM
            # but it makes no sense to be able to set this option per
            # test.
            @current_chain << File.open( filename, "rb") {|io| io.read}
            @word_conn.blocking_write( filename, delivery_options['norepair'] )
            # As soon as the deliver method doesn't raise an exception, we lose interest.
            @monitor.stop_monitoring
            status='success'
        rescue Exception=>e
            warn "#{COMPONENT}:#{VERSION}: Delivery exception: #{$!}" if @agent_options[:debug]
            @monitor.stop_monitoring
            if @monitor.fatal_exception?
                status='crash'
                exception_data=@monitor.exception_data
                dump=@monitor.minidump if delivery_options['minidump']
                chain=@current_chain if delivery_options['filechain']
                start_clean_word
                @monitor.reset
            else
                status='fail'
                # Word stays open, dirty.
            end
        end
        [status,exception_data,dump,chain]
    end

    def destroy
        @word_conn.close
        @monitor.reset
        @mi && @mi.close
        @mo && @mo.close
        @me && @me.close
        @mt.kill rescue nil
    end

    def method_missing( meth, *args )
        warn "MM: #{meth}" if @agent_options[:debug]
        @word_conn.send( meth, *args )
    end

end

