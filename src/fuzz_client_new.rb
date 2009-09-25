require 'rubygems'
require 'eventmachine'
require 'fileutils'
require 'base64'
require 'zlib'
require 'socket'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/objhax'


# This class is a generic class that can be inherited by task specific fuzzclients, to 
# do most of the work. It speaks my own Metafuzz protocol which is pretty much JSON
# serialized hashes, containing a verb and other parameters.
#
# In the overall structure, there will be one of these processes running on each
# fuzzclient handling the delivery of the test cases to the target and sending 
# back the results.
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
class FuzzClient < EventMachine::Connection

    VERSION="2.0.0"
    COMPONENT="FuzzClient"

    Queue=Hash.new {|hash, key| hash[key]=Array.new}
    Lookup=Hash.new {|hash, key| hash[key]=Hash.new}

    def self.new_ack_id
        @ack_id||=rand(2**31)
        @ack_id+=1
    end

    def self.setup( config_hsh={})
        default_config={
            'server_ip'=>"127.0.0.1",
            'server_port'=>10001,
            'work_dir'=>File.expand_path('C:/fuzzclient'),
            'poll_interval'=>60,
            'queue_name'=>'bulk'
        }
        @config=default_config.merge config_hsh
        @config.each {|k,v|
            meta_def k do v end
            meta_def k.to_s+'=' do |new_val| @config[k]=new_val end
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
    end

    # User should overload this function.
    def deliver(data,msg_id)
        # Deliver the test here, return the status and any extended
        # crash data (eg debugger output). Currently, the harness
        # uses 'success', 'fail', 'crash' and 'error'
        ['success', ""]
    end

    def dump_debug_data( msg_hash )
        begin
            port, ip=Socket.unpack_sockaddr_in( get_peername )
            puts "OUT: #{msg_hash['verb']}:#{msg_hash['ack_id'] rescue ''} to #{ip}:#{port}"
        rescue
            puts "OUT: #{msg_hash['verb']}:#{msg_hash['ack_id'] rescue ''}, not connected yet."
        end
    end

    # ---- Protocol Send functions

    # Used for the 'heartbeat' messages that get resent when things
    # are in an idle loop
    def start_idle_loop
        msg_hash={
            'verb'=>'client_ready',
            'queue'=>self.class.queue_name,
        }
        self.reconnect(self.class.server_ip, self.class.server_port) if self.error?
        dump_debug_data(msg_hash) if self.class.debug
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            Queue[:idle].shift
            puts "#{COMPONENT}: Timed out sending #{msg_hash['verb']}. Retrying."
            start_idle_loop
        end
        Queue[:idle] << waiter
        puts "idle loop started"
    end

    def cancel_idle_loop
        Queue[:idle].shift.succeed rescue nil
        raise RuntimeError, "#{COMPONENT}: idle queue not empty?" unless Queue[:idle].empty?
    end

    def send_message( msg_hash )
        # Don't replace the ack_id if it has one
        msg_hash['ack_id']=msg_hash['ack_id'] || self.class.new_ack_id
        self.reconnect(self.class.server_ip, self.class.server_port) if self.error?
        dump_debug_data(msg_hash) if self.class.debug
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
        waiter=OutMsg.new msg_hash
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            Lookup[:unanswered].delete(msg_hash['ack_id'])
            puts "#{COMPONENT}: Timed out sending #{msg_hash['verb']}. Retrying."
            send_message( msg_hash )
        end
        Lookup[:unanswered][msg_hash['ack_id']]=waiter
        puts "sent"
    rescue
        puts $!
    end

    def send_ack(ack_id, extra_data={})
        msg_hash={
            'verb'=>'ack_msg',
            'ack_id'=>ack_id,
        }
        msg_hash.merge! extra_data
        dump_debug_data(msg_hash) if self.class.debug
        # We only send one ack. If the ack gets lost and the sender cares
        # they will resend.
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
    rescue
        puts $!
    end
    # Protocol Receive functions

    def handle_deliver( msg )
        fuzzdata=Base64::decode64(msg.data)
        if Zlib.crc32(fuzzdata)==msg.crc32
            begin
                status,crash_details=deliver(fuzzdata,msg.server_id)
            rescue
                EventMachine::stop_event_loop
                raise RuntimeError, "Fuzzclient: Fatal error. Dying #{$!}"
            end
            if status=='crash'
                encoded_details=Base64::encode64(crash_details)
                send_ack(msg.ack_id, 'status'=>status, 'data'=>encoded_details)
            else
                send_ack(msg.ack_id, 'status'=>status)
            end
        else
            #ignore.
        end
        start_idle_loop
    end

    def handle_server_bye( msg )
        puts "Got server_bye: #{msg.data}"
        EventMachine::stop_event_loop
    end

    def post_init
        @handler=NetStringTokenizer.new
        puts "#{COMPONENT} #{VERSION}: Starting up..."
        start_idle_loop
    rescue
        puts $!
    end

    def receive_data(data)
        @handler.parse(data).each {|m|
            msg=FuzzMessage.new(m)
            if self.class.debug
                port, ip=Socket.unpack_sockaddr_in( get_peername )
                puts "IN: #{msg.verb}:#{msg.ack_id rescue ''} from #{ip}:#{port}"
            end
            cancel_idle_loop
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

end
