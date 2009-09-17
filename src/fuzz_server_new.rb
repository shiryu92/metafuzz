require 'rubygems'
require 'eventmachine'
require 'base64'
require 'zlib'
require 'digest/md5'
require 'socket'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/objhax'

# This class is a generic class that can be inherited by task specific fuzzservers, to 
# do most of the work. It speaks my own Metafuzz protocol which is pretty much JSON
# serialized hashes, containing a verb and other parameters.
#
# In the overall structure, this class is the broker between the production clients
# and the fuzz clients. It is single threaded, using the Reactor pattern, to make it
# easier to debug.
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
class TestCase < EventMachine::DefaultDeferrable
    attr_reader :data,:crc32,:encoding
    def initialize( data, crc, encoding=nil )
        @data=data
        @crc32=crc
        @encoding=encoding
        super()
    end
    alias :get_new_case :succeed
end

class DelayedResult < EventMachine::DefaultDeferrable
    alias :send_result :succeed
end

class FuzzServer < EventMachine::Connection

    VERSION="2.0.0"
    COMPONENT="FuzzServer"

    # --- Class stuff.

    Queue=Hash.new {|hash, key| hash[key]=Array.new}
    # Each of these queues is actually a hash of queues, to allow multiple
    # fuzzing runs simultaneously. EG the producer puts 'word' in
    # its message.queue and those messages will only get farmed out
    # to fuzzclients with a matching message.queue
    Queue[:fuzzclients]=Hash.new {|hash, key| hash[key]=Array.new}
    Queue[:test_cases]=Hash.new {|hash, key| hash[key]=Array.new}
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

    def self.next_server_id
        @server_id||=0
        @server_id+=1
    end

    def self.setup( config_hsh={})
        default_config={
            'agent_name'=>"SERVER",
            'server_ip'=>"0.0.0.0",
            'server_port'=>10001,
            'poll_interval'=>60,
            'debug'=>false,
            'work_dir'=>File.expand_path('~/fuzzserver'),
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
                    raise RuntimeError, "ProdctionClient: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "ProductionClient: Work directory unavailable. Exiting."
            end
        end
    end

    # --- Instance Methods

    def post_init
        puts "#{COMPONENT}  #{VERSION} starting up..."
        @handler=NetStringTokenizer.new
        @db_msg_queue=self.class.queue[:db_messages]
        @tc_queue=self.class.queue[:test_cases]
        @db_conn_queue=self.class.queue[:dbconns]
        @fuzzclient_queue=self.class.queue[:fuzzclients]
    end

    # --- Send functions

    def send_once( msg_hash )
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
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
    end

    def send_message( msg_hash, queue=nil )
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
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
        waiter=OutMsg.new msg_hash
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            self.class.lookup[:unanswered].delete(msg_hash['ack_id'])
            print "#{COMPONENT}: Timed out sending #{msg_hash['verb']}. "
            if queue
                queue << msg_hash
                print "Putting it back on the Queue.\n"
            else
                send_message msg_hash
                print "Resending it.\n"
            end
        end
        self.class.lookup[:unanswered][msg_hash['ack_id']]=waiter
    end

    def send_ack(ack_id, extra_data={})
        msg_hash={
            'verb'=>'ack_msg',
            'ack_id'=>ack_id,
        }
        msg_hash.merge! extra_data
        if self.class.debug
            begin
                port, ip=Socket.unpack_sockaddr_in( get_peername )
                puts "OUT: #{msg_hash['verb']}:#{msg_hash['ack_id']} to #{ip}:#{port}"
                sleep 1
            rescue
                puts "OUT: #{msg_hash['verb']}:#{msg_hash['ack_id']}, not connected."
                sleep 1
            end
        end
        # We only send one ack. If the ack gets lost and the sender cares
        # they will resend.
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
    end

    def db_send( msg_hash )
        # Don't add duplicates to the outbound db queue.
        unless @db_msg_queue.any? {|hsh| msg_hash==hsh}
            # If we have a ready DB, send the message, otherwise
            # put a callback in the queue.
            if dbconn=@db_conn_queue.shift
                dbconn.succeed msg_hash
            else
                # If it goes onto the outbound queue we don't add a timeout
                # because it will get sent when the next db_ready comes in
                # This would happen before the DB connects for the first
                # time, for example.
                @db_msg_queue << msg_hash
            end
        end
        if (len=@db_msg_queue.length) > 50
            puts "Fuzzserver: Warning: DB Queue > 50 items (#{len})"
        end
    end

    def send_result_to_db( server_id, template_hash, status, crashdata, crashfile )
        msg_hash={
            'verb'=>'test_result',
            'id'=>server_id,
            'template_hash'=>template_hash,
            'status'=>status,
            'encoding'=>'base64',
            'crashdata'=>crashdata,
            'crashfile'=>crashfile
        }
        db_send msg_hash
    end

    def send_template_to_db( template, template_hash )
        msg_hash={
            'verb'=>'new_template',
            'encoding'=>'base64',
            'template'=>Base64::encode64( template ),
            'template_hash'=>template_hash
        }
        db_send msg_hash
    end

    # --- Receive functions

    def handle_db_ready( msg )
        port, ip=Socket.unpack_sockaddr_in( get_peername )
        # If this DB is already ready, ignore its heartbeat
        # messages. UNLESS there is something in the db queue.
        unless self.class.lookup[:ready_dbs][ip+':'+port.to_s] and @db_msg_queue.empty?
            dbconn=EventMachine::DefaultDeferrable.new
            dbconn.callback do |msg_hash|
                send_message msg_hash, @db_msg_queue
            end
            if @db_msg_queue.empty?
                # we have nothing to send now, so this conn is ready
                @db_conn_queue << dbconn
                self.class.lookup[:ready_dbs][ip+':'+port.to_s]=true
            else
                # use this connection right away
                dbconn.succeed @db_msg_queue.shift
                # we just sent something, this conn is no longer ready until
                # we get a new db_ready from it.
                self.class.lookup[:ready_dbs][ip+':'+port.to_s]=false
            end
        else
            if self.class.debug
                puts "(already ready, no messages in queue, ignoring.)"
            end
        end
    end

    def handle_prodclient_ready( msg )
        port, ip=Socket.unpack_sockaddr_in( get_peername )
        # If this prodclient is already ready, ignore its heartbeat
        # messages.
        unless self.class.lookup[:ready_dbs][ip+':'+port.to_s]
            send_once('verb'=>'server_ready')
            dbconn=EventMachine::DefaultDeferrable.new
            dbconn.callback do |msg_hash|
                send_message msg_hash, @db_msg_queue
            end
            if @db_msg_queue.empty?
                # we have nothing to send now, so this conn is ready
                @db_conn_queue << dbconn
                self.class.lookup[:ready_dbs][ip+':'+port.to_s]=true
            else
                # use this connection right away
                dbconn.succeed @db_msg_queue.shift
                # we just sent something, this conn is no longer ready until
                # we get a new db_ready from it.
                self.class.lookup[:ready_dbs][ip+':'+port.to_s]=false
            end
        end
    end

    def handle_ack_msg( msg )
        waiter=self.class.lookup[:unanswered].delete( msg.ack_id )
        waiter.succeed
        stored_msg=waiter.msg_hash
        case stored_msg['verb']
        when 'test_result'
            dr=self.class.lookup[:delayed_results][stored_msg['server_id']]
            dr.succeed( stored_msg['result'], msg.db_id )
        end
        if self.class.debug
            puts "(ack of #{stored_msg['verb']})"
        end
    rescue
        if self.class.debug
            puts "(can't handle that ack, must be old)"
        end
    end

    # Users might want to overload this function.
    def handle_result( msg )
        server_id,result_status,crashdata,crashfile=msg.server_id, msg.status, msg.data, msg.crashfile
        template_hash=self.class.lookup[:template_tracker].delete server_id
        send_result_to_db(server_id, template_hash, result_status, crashdata, crashfile)
    end

    # Only comes from fuzzclients.
    def handle_client_ready( msg )
        if @tc_queue[msg.queue].empty?
            waiter=EventMachine::DefaultDeferrable.new
            waiter.callback do |server_id, test_case|
                msg_hash={
                    'verb'=>'deliver',
                    'encoding'=>test_case.encoding,
                    'data'=>test_case.data,
                    'server_id'=>server_id,
                    'crc32'=>test_case.crc32
                }
                send_message msg_hash, @tc_queue[msg.queue]
                test_case.get_new_case
            end
            @fuzzclient_queue[msg.queue] << waiter
        else
            server_id,test_case=@tc_queue[msg.queue].shift
            msg_hash={
                'verb'=>'deliver',
                'encoding'=>test_case.encoding,
                'data'=>test_case.data,
                'server_id'=>server_id,
                'crc32'=>test_case.crc32
            }
            send_message msg_hash, @tc_queue[msg.queue] 
            test_case.get_new_case
        end
    end

    def handle_client_startup( msg )
        if msg.client_type=='production'
            begin
                template=Base64::decode64(msg.template)
                unless Zlib.crc32(template)==msg.crc32
                    raise RuntimeError, "FuzzServer: ProdClient template CRC fail."
                end
                template_hash=Digest::MD5.hexdigest(template)
                unless self.class.lookup[:templates][template_hash]
                    self.class.lookup[:templates][template_hash]=true
                    send_template_to_db(template, template_hash)
                end
            rescue
                raise RuntimeError, "FuzzServer: Prodclient template error: #{$!}"
            end
        end
        send_ack msg.ack_id
        send_once('verb'=>'server_ready')
    end

    def handle_new_test_case( msg )
        unless @tc_queue[msg.queue].any? {|id,tc| tc.crc32==msg.crc32 }
            if self.class.lookup[:templates][msg.template_hash]
                server_id=self.class.next_server_id
                self.class.lookup[:template_tracker][server_id]=msg.template_hash
                # Prepare this test case for delivery
                test_case=TestCase.new(msg.data, msg.crc32, msg.encoding)
                test_case.callback do
                    send_once('verb'=>'server_ready')
                end
                if waiting=@fuzzclient_queue[msg.queue].shift
                    waiting.succeed(server_id,test_case)
                else
                    @tc_queue[msg.queue] << [server_id, test_case]
                end
                # Create a callback, so we can let the prodclient know once this
                # result is in the database.
                dr=DelayedResult.new
                dr.callback do |result, db_id|
                    extra_data={
                        'result'=>result,
                        'db_id'=>db_id,
                    }
                    send_ack msg.ack_id, extra_data
                end
                self.class.lookup[:delayed_results][server_id]=dr
            else
                send_once('verb'=>'reset')
            end
        else
            if self.class.debug
                puts "Ignoring duplicate #{msg.ack_id}"
            end
        end
    end

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
