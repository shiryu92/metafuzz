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
    attr_reader :data, :crc32, :ack_id
    def initialize( data, crc, ack_id )
        @data=data
        @crc32=crc
        @ack_id=ack_id
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
    QUEUE_MAXLEN=50

    # --- Class stuff.

    Queue=Hash.new {|hash, key| hash[key]=Array.new}
    # The fuzzclient and test case queues are actually hashes of
    # queues, to allow for multiple fuzzing runs simultaneously. 
    # EG the producer puts 'word' in its message.queue and those 
    # messages will only get farmed out to fuzzclients with a 
    # matching message.queue
    Queue[:fuzzclients]=Hash.new {|hash, key| hash[key]=Array.new}
    Queue[:test_cases]=Hash.new {|hash, key| hash[key]=Array.new}
    Lookup=Hash.new {|hash, key| hash[key]=Hash.new}

    def self.new_ack_id
        @ack_id||=rand(2**31)
        @ack_id+=1
    end

    def self.next_server_id
        @server_id||=rand(2**31)
        @server_id+=1
    end

    def self.setup( config_hsh={})
        default_config={
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
        @db_msg_queue=Queue[:db_messages]
        @tc_queue=Queue[:test_cases]
        @db_conn_queue=Queue[:dbconns]
        @fuzzclient_queue=Queue[:fuzzclients]
    end

    # --- Send functions

    def dump_debug_data( msg_hash )
        begin
            port, ip=Socket.unpack_sockaddr_in( get_peername )
            puts "OUT: #{msg_hash['verb']}:#{msg_hash['ack_id'] rescue ''}  to #{ip}:#{port}"
            sleep 1
        rescue
            puts "OUT: #{msg_hash['verb']}, not connected yet."
            sleep 1
        end
    end

    def send_once( msg_hash )
        dump_debug_data( msg_hash ) if self.class.debug
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
    end

    def send_message( msg_hash, queue=nil )
        # The idea here is that if we want the message delivered
        # to one specific host, we don't pass a queue and it gets
        # resent. For stuff like tests, we don't care who gets them
        # so we just put them back in the outbound queue if they
        # time out.
        # Don't replace the ack_id if it has one
        msg_hash['ack_id']=msg_hash['ack_id'] || self.class.new_ack_id
        dump_debug_data( msg_hash ) if self.class.debug
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
        waiter=OutMsg.new msg_hash
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            Lookup[:unanswered].delete(msg_hash['ack_id'])
            print "#{COMPONENT}: Timed out sending #{msg_hash['verb']}#{msg_hash['ack_id'] rescue ''}. "
            if queue
                queue << msg_hash
                print "Putting it back on the Queue.\n"
            else
                send_message msg_hash
                print "Resending it.\n"
            end
        end
        Lookup[:unanswered][msg_hash['ack_id']]=waiter
    end

    def send_ack(ack_id, extra_data={})
        msg_hash={
            'verb'=>'ack_msg',
            'ack_id'=>ack_id,
        }
        msg_hash.merge! extra_data
        dump_debug_data( msg_hash ) if self.class.debug
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
            'crashdata'=>crashdata,
            'crashfile'=>crashfile
        }
        db_send msg_hash
    end

    def send_template_to_db( template, template_hash )
        msg_hash={
            'verb'=>'new_template',
            'template'=>Base64::encode64( template ),
            'template_hash'=>template_hash
        }
        db_send msg_hash
    end

    # --- Receive functions

    def handle_db_ready( msg )
        port, ip=Socket.unpack_sockaddr_in( get_peername )
        # If this DB is already ready, ignore its heartbeat
        # messages, UNLESS there is something in the db queue.
        # (which can happen depending on the order in which stuff
        # starts up or restarts)
        unless Lookup[:ready_dbs][ip+':'+port.to_s] and @db_msg_queue.empty?
            dbconn=EventMachine::DefaultDeferrable.new
            dbconn.callback do |msg_hash|
                send_message msg_hash, @db_msg_queue
            end
            if @db_msg_queue.empty?
                # we have nothing to send now, so this conn is ready
                # and goes in the queue
                @db_conn_queue << dbconn
                Lookup[:ready_dbs][ip+':'+port.to_s]=true
            else
                # use this connection right away
                dbconn.succeed @db_msg_queue.shift
                # we just sent something, this conn is no longer ready until
                # we get a new db_ready from it.
                Lookup[:ready_dbs][ip+':'+port.to_s]=false
            end
        else
            if self.class.debug
                puts "(already ready, no messages in queue, ignoring.)"
            end
        end
    end

    def handle_ack_msg( msg )
        stored_msg=Lookup[:unanswered][msg.ack_id].msg_hash
        case stored_msg['verb']
        when 'test_result'
            dr=Lookup[:delayed_results].delete( stored_msg['server_id'] )
            dr.send_result( stored_msg['result'], msg.db_id )
            Lookup[:unanswered].delete( msg.ack_id ).succeed
        when 'deliver'
            puts 'extending timeout'
            Lookup[:unanswered][msg.ack_id].timeout(self.class.poll_interval * 2)
        else
            Lookup[:unanswered].delete( msg.ack_id ).succeed
        end
        if self.class.debug
            puts "(ack of #{stored_msg['verb']})"
        end
    rescue
        if self.class.debug
            puts $!
            puts "(can't handle that ack, must be old)"
        end
    end

    # Users might want to overload this function.
    def handle_result( msg )
        server_id,result_status,crashdata,crashfile=msg.server_id, msg.status, msg.data, msg.crashfile
        send_ack msg.ack_id # always ack the message.
        # If this result isn't in the delayed result hash
        # there is something wrong.
        if Lookup[:delayed_results].has_key? server_id
            template_hash=Lookup[:template_tracker].delete server_id
            # crashdata and crashfile are both b64 encoded.
            send_result_to_db(server_id, template_hash, result_status, crashdata, crashfile)
        else
            # We can't handle this result. Probably the server
            # restarted while the fuzzclient had a result from
            # a previous run. Ignore.
        end
    rescue
        puts $!
    end

    # Only comes from fuzzclients.
    def handle_client_ready( msg )
        if @tc_queue[msg.queue].empty?
            # Ignore, if the queue is too long.
            if @fuzzclient_queue[msg.queue].length < QUEUE_MAXLEN
                waiter=EventMachine::DefaultDeferrable.new
                waiter.callback do |msg_hash|
                    send_message msg_hash, @tc_queue[msg.queue]
                end
                @fuzzclient_queue[msg.queue] << waiter
            end
        else
            msg_hash=@tc_queue[msg.queue].shift
            send_message msg_hash, @tc_queue[msg.queue] 
        end
    end

    def handle_client_startup( msg )
        # Actually, the production client is the only one
        # that sends a client_startup, now..
        if msg.client_type=='production'
            begin
                template=Base64::decode64(msg.template)
                unless Zlib.crc32(template)==msg.crc32
                    puts "#{COMPONENT}: ProdClient template CRC fail."
                    send_once('verb'=>'reset')
                end
                template_hash=Digest::MD5.hexdigest(template)
                unless Lookup[:templates].has_key? template_hash
                    Lookup[:templates][template_hash]=true
                    send_template_to_db(template, template_hash)
                end
            rescue
                raise RuntimeError, "#{COMPONENT}: Prodclient template error: #{$!}"
            end
        end
        send_ack msg.ack_id
    end

    def handle_new_test_case( msg )
        unless @tc_queue[msg.queue].any? {|msg_hash| msg_hash['producer_ack_id']==msg.ack_id }
            if Lookup[:templates].has_key? msg.template_hash
                server_id=self.class.next_server_id
                Lookup[:template_tracker][server_id]=msg.template_hash
                msg_hash={
                    'verb'=>'deliver',
                    'data'=>msg.data,
                    'server_id'=>server_id,
                    'producer_ack_id'=>msg.ack_id,
                    'crc32'=>msg.crc32
                }
                if waiting=@fuzzclient_queue[msg.queue].shift
                    waiting.succeed msg_hash
                else
                    @tc_queue[msg.queue] << msg_hash
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
                Lookup[:delayed_results][server_id]=dr
            else
                # We don't have this template, get the producer to
                # resend it. Probably a restart screwed things up.
                send_once('verb'=>'reset')
            end
        else
            if self.class.debug
                puts "Ignoring duplicate #{msg.ack_id}"
            end
        end
    rescue
        puts $!
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
