require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'fuzzprotocol'
require 'fileutils'
require 'objhax'
require 'base64'
require 'zlib'


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
    def self.queue
        Queue
    end

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
            'work_dir'=>File.expand_path('C:/fuzzclient'),
            'poll_interval'=>60,
            'queue_name'=>'bulk',
            'paranoid'=>false
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
        @unanswered=[]
        class << self
            attr_reader :unanswered
        end
    end

    def post_init
        @handler=NetStringTokenizer.new
        puts "#{COMPONENT} #{VERSION}: Starting up..."
        send_client_startup
        start_idle_loop
    end

    # User should overload this function.
    def deliver(data,msg_id)
        # Deliver the test here, return the status and any extended
        # crash data (eg debugger output). Currently, the harness
        # uses 'success', 'fail', 'crash' and 'error'
        ['success', ""]
    end

    # Protocol Send functions

    # Used for the 'heartbeat' messages that get resent when things
    # are in an idle loop
    def start_idle_loop
        msg_hash={
            'verb'=>'client_ready',
            'queue'=>self.class.queue_name,
        }
        if self.class.debug
            begin
                port, ip=Socket.unpack_sockaddr_in( get_peername )
                puts "OUT: #{msg_hash['verb']} to #{ip}:#{port}"
                sleep 1
            rescue
                puts "OUT: #{msg_hash['verb']}, not connected yet."
                sleep 1
            end
        end
        self.reconnect(self.class.fuzzserver_ip,self.class.fuzzserver_port) if self.error?
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            self.class.queue[:idle].shift
            puts "#{COMPONENT}: Timed out sending #{msg_hash['verb']}. Retrying."
            start_idle_loop
        end
        self.class.queue[:idle] << waiter
    end

    def cancel_idle_loop
        self.class.queue[:idle].shift.succeed
        raise RuntimeError, "#{COMPONENT}: idle queue not empty?" unless self.class.queue[:idle].empty?
    end

    def send_message( msg_hash )
        # Don't replace the ack_id if it has one
        msg_hash={'ack_id'=>self.class.new_ack_id}.merge msg_hash
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
            self.class.lookup[:unanswered].delete(msg_hash['ack_id'])
            puts "#{COMPONENT}: Timed out sending #{msg_hash['verb']}. Retrying."
            send_message( msg_hash )
        end
        self.class.lookup[:unanswered][msg_hash['ack_id']]=waiter
    end

    def send_client_startup
        send_message(
            'verb'=>'client_startup',
            'station_id'=>self.class.agent_name,
            'client_type'=>'fuzz',
            'queue'=>self.class.queue_name,
            'data'=>""
        )
    end

    def send_result(server_id, status, crash_details=false, fuzzfile=false)
        send_message(
            'verb'=>'result',
            'station_id'=>self.class.agent_name,
            'server_id'=>server_id,
            'status'=>status,
            'data'=>crash_details,
            'queue'=>self.class.queue_name,
            'crashfile'=>fuzzfile
        )
    end

    # Protocol Receive functions

    def handle_ack_msg( msg )
        waiter=self.class.lookup[:unanswered].delete( msg.ack_id )
        waiter.succeed
        stored_msg=waiter.msg_hash
        if self.class.debug
            puts "(ack of #{stored_msg['verb']})"
        end
    rescue
        if self.class.debug
            puts "(can't handle that ack, must be old.)"
        end
    end

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
                send_result msg.server_id, status, crash_details, msg.data
            else
                send_result msg.server_id, status
            end
        else
            #ignore.
        end
        start_idle_loop
    end

    def handle_server_ready( msg )
        start_idle_loop
    end

    def handle_server_bye( msg )
        # In this version, this is used to send errors. Before, it just
        # called EventMachine::stop_event_loop.
        puts "Got server_bye: #{msg.data}"
        EventMachine::stop_event_loop
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

    def receive_data(data)
        @handler.parse(data).each {|m|
            msg=FuzzMessage.new(m)
            if self.class.debug
                port, ip=Socket.unpack_sockaddr_in( get_peername )
                puts "IN: #{msg.verb}:#{msg.ack_id rescue ''} from #{ip}:#{port}"
                sleep 1
            end
            cancel_idle_loop
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end
end
