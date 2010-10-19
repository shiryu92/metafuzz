require File.dirname(__FILE__) + '/../core/connector'
require File.dirname(__FILE__) + '/conn_office'
require File.dirname(__FILE__) + '/conn_cdb'
require File.dirname(__FILE__) + '/drb_debug_client'
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
        'maxchain'=>15,
        'ignore_exceptions'=>[]
    }

    AGENT_DEFAULTS={
        'debug'=>false,
        'visible'=>true
    }

    def initialize( arg_hash={} )
        @agent_options=AGENT_DEFAULTS.merge( arg_hash )
        # Start with high priority for better chance of killing processes pegging the CPU
        warn "#{COMPONENT}:#{VERSION}: Starting monitor server..." if @agent_options['debug']
        system("start cmd /k ruby monitor.rb #{(@agent_options['debug']? '-d' : ' ')}")
        @monitor=DRbObject.new(nil, "druby://127.0.0.1:8888")
        @current_chain=[]
        warn "#{COMPONENT}:#{VERSION}: Startup done!" if @agent_options['debug']
    end

    def start_clean_word
        warn "#{COMPONENT}:#{VERSION}: Starting clean Word process.." if @agent_options['debug']
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
        warn "#{COMPONENT}:#{VERSION}: New Word process pid #{@current_pid}." if @agent_options['debug']
        @word_conn.set_visible if @agent_options['visible']
        @current_chain.clear
    end

    def setup_for_delivery( delivery_options )
        begin
            5.times do
                begin
                    start_clean_word
                    @monitor.start( @word_conn.pid, @word_conn.wid, delivery_options )
                    break
                rescue
                    warn "#{COMPONENT}:#{VERSION}: Failed to setup for delivery. Retrying. #{$!}" if @agent_options['debug']
                    sleep 1
                end
            end
        rescue StandardError=>e
            warn e.backtrace
            raise "#{COMPONENT}:#{VERSION}: Failed to setup for delivery. Fatal."
        end
    end

    def deliver( filename, delivery_options={} )
        status='error'
        exception_data=''
        dump='' # not implemented yet
        chain=''
        delivery_options=DELIVERY_DEFAULTS.merge( delivery_options )
        if delivery_options['clean'] or not (@word_conn && @word_conn.connected?)
            setup_for_delivery( delivery_options )
        else
            begin
                @monitor.new_test
            rescue
                setup_for_delivery( delivery_options )
            end
        end
        # Always keep file chains, but only send them back
        # when the filechain option is set. Uses more RAM
        # but it makes no sense to be able to set this option per
        # test.
        @current_chain << File.open( filename, "rb") {|io| io.read}
        begin
            @word_conn.blocking_write( filename, delivery_options['norepair'] )
            # As soon as the deliver method doesn't raise an exception, we lose interest.
            raise "Not running" unless @monitor.running?
            status='success'
        rescue StandardError=>e
            unless @monitor.running?
                # potential infinite loop :(
                warn "#{COMPONENT}:#{VERSION}: Monitor reports fault. Delivering again." if @agent_options['debug']
                setup_for_delivery( delivery_options )
                retry
            end
            if @monitor.exception_data
                status='crash'
                exception_data=@monitor.exception_data
                dump=@monitor.minidump if delivery_options['minidump']
                chain=@current_chain if delivery_options['filechain']
                warn "#{COMPONENT}:#{VERSION}: Chain length #{@current_chain.size}" if @agent_options['debug']
            else
                if @monitor.hang?
                    status='hang'
                else
                    status='fail'
                end
                #warn "#{COMPONENT}:#{VERSION}: Delivery exception: #{$!}, #{e.backtrace}" if @agent_options['debug']
                # Word stays open, dirty.
            end
        end
        if status=='crash' or delivery_options['clean'] or @current_chain.size >= delivery_options['maxchain']
            @word_conn.close
            @word_conn=nil
            @monitor.reset
        end
        @word_conn.close_documents rescue nil
        [status,exception_data,dump,chain]
    end

    def destroy
        warn "#{COMPONENT}:#{VERSION}: Received destroy..." if @agent_options['debug']
        @word_conn.close rescue nil
        @monitor.destroy
    end

    def method_missing( meth, *args )
        warn "MM: #{meth}" if @agent_options[:debug]
        @word_conn.send( meth, *args )
    end

end
