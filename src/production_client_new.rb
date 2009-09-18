require 'rubygems'
require 'eventmachine'
require 'fileutils'
require 'objhax'
require 'base64'
require 'zlib'
require 'digest/md5'
require 'socket'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'

# This class is a generic class that can be inherited by task specific production clients, to 
# do most of the work. It speaks my own Metafuzz protocol which is pretty much JSON
# serialized hashes, containing a verb and other parameters.
#
# In the overall structure, one or more of these will feed test cases to the fuzz server.
# In a more complicated implementation it would also be able to adapt, based on the results.
#
# To be honest, if you don't understand this part, (which is completely fair) 
# you're better off reading the EventMachine documentation, not mine.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

class ProductionClient < EventMachine::Connection

    COMPONENT="ProdClient"
    VERSION="2.0.0"

    Lookup=Hash.new {|hash, key| hash[key]=Hash.new}
    def self.lookup
        Lookup
    end

    def self.new_ack_id
        @ack_id||=rand(2**31)
        @ack_id+=1
    end

    def self.setup( config_hsh={})
        default_config={
            'server_ip'=>"127.0.0.1",
            'server_port'=>10001,
            'work_dir'=>File.expand_path('~/prodclient'),
            'poll_interval'=>60,
            'production_generator'=>Producer.new,
            'queue_name'=>'bulk',
            'debug'=>false,
            'template'=>Producer.const_get( :Template )
        }
        @config=default_config.merge config_hsh
        @config.each {|k,v|
            meta_def k do v end
            meta_def k.to_s+'=' do |new| @config[k]=new end
        }
        unless File.directory? @config['work_dir']
            print "Work directory #{@config['work_dir']} doesn't exist. Create it? [y/n]: "
            answer=STDIN.gets.chomp
            if answer =~ /^[yY]/
                begin
                    Dir.mkdir(@config['work_dir'])
                rescue
                    raise RuntimeError, "#{COMPONENT}: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "#{COMPONENT}: Work directory unavailable. Exiting."
            end
        end
        @case_id=0
        @template_hash=Digest::MD5.hexdigest(template)
        class << self
            attr_accessor :case_id, :template_hash
        end
    end

    # --- Send methods

    def send_message( msg_hash )
        # Don't replace the ack_id if it has one
        msg_hash['ack_id']=msg_hash['ack_id'] || self.class.new_ack_id
        if self.class.debug
            begin
                port, ip=Socket.unpack_sockaddr_in( get_peername )
                puts "OUT: #{msg_hash['verb']}:#{msg_hash['ack_id']} to #{ip}:#{port}"
                sleep 1
            rescue
                puts "OUT: #{msg_hash['verb']}:#{msg_hash['ack_id']}, not connected yet."
                sleep 1
            end
        end
        self.reconnect(self.class.server_ip,self.class.server_port) if self.error?
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
        waiter=OutMsg.new msg_hash
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            Lookup[:unanswered].delete(msg_hash['ack_id'])
            puts "#{COMPONENT}: Timed out sending #{msg_hash['verb']}. Retrying."
            send_message( msg_hash )
        end
        Lookup[:unanswered][msg_hash['ack_id']]=waiter
    end

    def send_test_case( tc, case_id, crc )
        send_message(
            'verb'=>'new_test_case',
            'id'=>case_id,
            'crc32'=>crc,
            'data'=>tc,
            'queue'=>self.class.queue_name,
            'template_hash'=>self.class.template_hash
        )
    end

    def send_client_bye
        send_message(
            'verb'=>'client_bye',
            'client_type'=>'production',
            'queue'=>self.class.queue_name,
        )
    end

    def send_client_startup
        send_message(
            'verb'=>'client_startup',
            'client_type'=>'production',
            'template'=>Base64.encode64( self.class.template ),
            'crc32'=>Zlib.crc32( self.class.template ),
        )
    end

    def send_next_case
        if self.class.production_generator.next?
            self.class.case_id+=1
            raw_test=self.class.production_generator.next
            crc=Zlib.crc32(raw_test)
            encoded_test=Base64.encode64 raw_test
            send_test_case encoded_test, self.class.case_id, crc
        else
            send_client_bye
            puts "All done, exiting."
            EventMachine::stop_event_loop
        end
    end

    # Receive methods...

    def handle_ack_msg( msg )
        waiter=Lookup[:unanswered].delete( msg.ack_id )
        waiter.succeed
        stored_msg=waiter.msg_hash
        unless stored_msg['verb']=='client_bye'
            send_next_case
        end
        if self.class.debug
            puts "(ack of #{stored_msg['verb']})"
        end
    rescue
        if self.class.debug
            puts "(can't handle that ack, must be old.)"
        end
    end

    def handle_reset( msg )
        # Note that we don't cancel unacked test cases or
        # restart the production generator, we just send
        # the startup so the server will get our template
        send_client_startup
    end

    # This shouldn't be used, now...
    def handle_server_ready( msg )
        send_next_case
    end

    def handle_server_bye( msg )
        # In the current protocol, this isn't used, but may as well
        # leave the handler around, just in case.
        puts "Got server_bye, exiting."
        EventMachine::stop_event_loop
    end

    def post_init
        @handler=NetStringTokenizer.new
        puts "#{COMPONENT} #{VERSION}: Trying to connect to #{self.class.server_ip} : #{self.class.server_port}" 
        send_client_startup
    rescue
        puts $!
        EventMachine::stop_event_loop
    end

    # FuzzMessage#verb returns a string so self.send activates
    # the corresponding 'handle_' instance method above, 
    # and passes the message itself as a parameter.
    def receive_data(data)
        @handler.parse(data).each {|m| 
            msg=FuzzMessage.new(m)
            if self.class.debug
                port, ip=Socket.unpack_sockaddr_in( get_peername )
                puts "IN: #{msg.verb}:#{msg.ack_id rescue ''} from #{ip}:#{port}"
                sleep 1
            end
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end
end
