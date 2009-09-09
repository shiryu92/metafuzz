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

    VERSION="1.2.0"
    def self.setup( config_hsh={})
        default_config={
            'agent_name'=>"CLIENT1",
            'server_ip'=>"127.0.0.1",
            'server_port'=>10001,
            'work_dir'=>File.expand_path('C:/fuzzclient'),
            'poll_interval'=>60,
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
                    raise RuntimeError, "FuzzClient: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "FuzzClient: Work directory unavailable. Exiting."
            end
        end
        @unanswered=[]
        class << self
            attr_reader :unanswered
        end
    end

    def post_init
        @handler=NetStringTokenizer.new
        puts "FuzzClient#{VERSION}: Starting up..."
        send_client_startup
    end

    def deliver(data,msg_id)
        # Deliver the test here, return the status and any extended
        # crash data (eg debugger output). Currently, the harness
        # uses 'success', 'fail', 'crash' and 'error'
        ['success', ""]
    end

    # Protocol Send functions

    def send_message( msg_hash )
        self.reconnect(self.class.server_ip,self.class.server_port) if self.error?
        send_data @handler.pack(FuzzMessage.new(msg_hash))
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            self.class.unanswered.delete waiter
            puts "Fuzzclient: Timed out sending #{msg_hash['verb']}. Retrying."
            send_message( msg_hash )
        end
        self.class.unanswered << waiter
    end

    def send_client_startup
        send_message(
            'verb'=>'client_startup',
            'station_id'=>self.class.agent_name,
            'client_type'=>'fuzz',
            'data'=>""
        )
    end

    def send_client_ready
        send_message(
            'verb'=>'client_ready',
            'station_id'=>self.class.agent_name,
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
            'crashfile'=>fuzzfile
        )
    end

    # Protocol Receive functions

    def handle_deliver( msg )
        case msg.encoding
        when 'base64'
            fuzzdata=Base64::decode64(msg.data)
        else
            fuzzdata=msg.data
        end
        if self.class.paranoid
            unless Zlib.crc32(fuzzdata)==msg.crc32
                raise RuntimeError, "Fuzzclient: data corruption, mismatched CRC32."
            end
        end
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
        send_client_ready
    end

    def handle_server_ready( msg )
        send_client_ready
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
        # Cancel the outstanding retries.
        # This doesn't actually guarantee that we're in sync, but it's
        # good enough for government work.
        self.class.unanswered.shift.succeed until self.class.unanswered.empty?
        @handler.parse(data).each {|m|
            msg=FuzzMessage.new(m)
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end
end
