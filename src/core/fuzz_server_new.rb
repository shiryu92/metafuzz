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

class FuzzServer < HarnessComponent

    VERSION="2.2.0"
    COMPONENT="FuzzServer"
    DEFAULT_CONFIG={
        'listen_ip'=>"0.0.0.0",
        'listen_port'=>10001,
        'poll_interval'=>5,
        'fuzzbot_timeout'=>60,
        'debug'=>false,
        'dummy'=>false,
        'queue_shedding'=>false,
        'dbq_max'=>50,
        'work_dir'=>File.expand_path('~/fuzzserver'),
    }

    # --- Class stuff.

    def self.setup( *args )
        super
        # The fuzzclient and test case queues are actually hashes of
        # queues, to allow for multiple fuzzing runs simultaneously. 
        # EG the producer puts 'word' in its message.queue and those 
        # messages will only get farmed out to fuzzclients with a 
        # matching message.queue
        queue[:fuzzclients]=Hash.new {|hash, key| hash[key]=Array.new}
        queue[:test_cases]=Hash.new {|hash, key| hash[key]=Array.new}
        lookup[:summary]=Hash.new {|h,k| h[k]=0}
        lookup[:ready_fuzzclients]=Hash.new {|h,k| h[k]=Hash.new}
    end

    def self.next_server_id
        @server_id||=rand(2**31)
        @server_id+=1
    end

    # --- Instance Methods

    def post_init
        # Makes the rest of the code more readable...
        @db_msg_queue=self.class.queue[:db_messages]
        @tc_queue=self.class.queue[:test_cases]
        @db_conn_queue=self.class.queue[:dbconns]
        @fuzzclient_queue=self.class.queue[:fuzzclients]
        @ready_dbs=self.class.lookup[:ready_dbs]
        @ready_fuzzclients=self.class.lookup[:ready_fuzzclients]
        @templates=self.class.lookup[:templates]
        @unanswered=self.class.lookup[:unanswered]
        @delayed_results=self.class.lookup[:delayed_results]
        @delivery_receipts=self.class.lookup[:delivery_receipts]
        @template_tracker=self.class.lookup[:template_tracker]
        @summary=self.class.lookup[:summary]
    end

    def process_result( arg_hsh )
        # If this result isn't in the delayed result hash
        # there is something wrong.
        if @delayed_results.has_key? arg_hsh[:server_id]
            template_hash=@template_tracker.delete arg_hsh[:server_id]
            # crashdata and crashfile are both b64 encoded, if present
            send_result_to_db(arg_hsh[:server_id],
                              template_hash,
                              arg_hsh[:result],
                              arg_hsh[:crashdata],
                              arg_hsh[:crashfile],
                              arg_hsh[:crc32]
                             ) unless self.class.dummy
                             @summary['total']+=1
                             @summary[arg_hsh[:result]]+=1
        else
            # We can't handle this result. Probably the server
            # restarted while the fuzzclient had a result from
            # a previous run. Ignore.
            puts "Bad result #{msg.ack_id}" if self.class.debug
        end
    rescue
        puts $!
    end

    # --- Send functions

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
        if (len=@db_msg_queue.length) > self.class.dbq_max
            # Note that the dbq_max isn't the real maximum - if many fuzzbots
            # are in the process of delivering, once the queue max is hit we
            # still need to accept their results, so we have to queue them for the DB...
            if self.class.debug
                puts "Fuzzserver: SHEDDING: DBQ > configured max of #{self.class.dbq_max} items (#{len})"
            end
            self.class.queue_shedding=true
        end
    end

    def send_result_to_db( server_id, template_hash, status, crashdata, crashfile, crc32 )
        msg_hash={
            'verb'=>'test_result',
            'server_id'=>server_id,
            'template_hash'=>template_hash,
            'status'=>status,
            'crashdata'=>crashdata,
            'crc32'=>crc32,
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

    # Acks might need special processing, if they contain additional
    # information, such as the acks to test_result and deliver
    # messages.
    def handle_ack_msg( their_msg )
        begin
            our_stored_msg=super
            case our_stored_msg['verb']
            when 'test_result'
                dr=@delayed_results.delete( our_stored_msg['server_id'])
                dr.succeed( our_stored_msg['status'], their_msg.db_id )
            when 'deliver'
                unless their_msg.status=='error'
                    if their_msg.status=='crash'
                        process_result(
                            :server_id=>our_stored_msg['server_id'],
                            :result=>their_msg.status,
                            :crashdata=>(their_msg.data rescue nil),
                            :crashfile=>our_stored_msg['data'],
                            :crc32=>our_stored_msg['crc32']
                        )
                    else
                        process_result(
                            :server_id=>our_stored_msg['server_id'],
                            :result=>their_msg.status,
                            :crashdata=>nil,
                            :crashfile=>nil,
                            :crc32=>our_stored_msg['crc32']
                        )
                    end
                end
            else
                # nothing extra to do.
            end
        rescue Exception => e
            puts e.backtrace
            puts "Weird, failed in handle_ack_msg"
            p their_msg
        end
    end

    def handle_db_ready( msg )
        port, ip=Socket.unpack_sockaddr_in( get_peername )
        # If this DB is already ready, ignore its heartbeat
        # messages, UNLESS there is something in the db queue.
        # (which can happen depending on the order in which stuff
        # starts up or restarts)
        if @ready_dbs[ip+':'+port.to_s] and @db_msg_queue.empty?
            if self.class.debug
                puts "(DB already ready, no messages in queue, ignoring.)"
            end
        else
            dbconn=EventMachine::DefaultDeferrable.new
            dbconn.callback do |msg_hash|
                send_message msg_hash, @db_msg_queue
                # we just sent something, this conn is no longer ready until
                # we get a new db_ready from it.
                @ready_dbs[ip+':'+port.to_s]=false
            end
            if @db_msg_queue.empty?
                # we have nothing to send now, so this conn is ready
                # and goes in the queue
                @db_conn_queue << dbconn
                @ready_dbs[ip+':'+port.to_s]=true
                puts "SHEDDING OVER" if self.class.queue_shedding and self.class.debug
                self.class.queue_shedding=false
            else
                # use this connection right away
                dbconn.succeed @db_msg_queue.shift
            end
        end
    end

    # Only comes from fuzzclients. Same idea as handle_db_ready (above).
    def handle_client_ready( msg )
        port, ip=Socket.unpack_sockaddr_in( get_peername )
        if @ready_fuzzclients[msg.queue][ip+':'+port.to_s] and (@tc_queue[msg.queue].empty? || self.class.queue_shedding)
            if self.class.debug
                puts "(fuzzclient already ready, no messages in queue, ignoring.)"
            end
        else
            clientconn=EventMachine::DefaultDeferrable.new
            # If the message has been redelivered there will be no receipt
            # anymore, because send_message takes only a msg_hash and a
            # queue. Since we already told the producer that we had accepted 
            # the message for delivery, this is not a problem.
            clientconn.callback do |msg_hash, receipt|
                receipt.succeed rescue nil
                send_message msg_hash, @tc_queue[msg.queue], self.class.fuzzbot_timeout
                @ready_fuzzclients[msg.queue][ip+':'+port.to_s]=false
            end
            if @tc_queue[msg.queue].empty?
                @ready_fuzzclients[msg.queue][ip+':'+port.to_s]=true
                @fuzzclient_queue[msg.queue] << clientconn
                puts "Starving" if self.class.debug
            else
                if self.class.queue_shedding
                    # queue this until the queue is under control.
                    @ready_fuzzclients[msg.queue][ip+':'+port.to_s]=true
                    @fuzzclient_queue[msg.queue] << clientconn
                else
                    clientconn.succeed @tc_queue[msg.queue].shift
                end
            end
        end
    end

    def handle_client_startup( msg )
        # Actually, the production client is the only one
        # that sends a client_startup, now..
        if msg.client_type=='production'
            begin
                template=Base64::decode64(msg.template)
                unless Zlib.crc32(template)==msg.crc32
                    puts "#{self.class.component}: ProdClient template CRC fail."
                    send_once('verb'=>'reset')
                end
                template_hash=Digest::MD5.hexdigest(template)
                unless @templates.has_key? template_hash
                    @templates[template_hash]=true
                    send_template_to_db(template, template_hash)
                end
            rescue
                raise RuntimeError, "#{self.class.component}: Prodclient template error: #{$!}"
            end
        end
        send_ack msg.ack_id
    end

    def handle_new_test_case( msg )
        unless @tc_queue[msg.queue].any? {|msg_hash, receipt| msg_hash['producer_ack_id']==msg.ack_id }
            if @templates.has_key? msg.template_hash
                server_id=self.class.next_server_id
                @template_tracker[server_id]=msg.template_hash
                # Note: we send two acks. Once when the test has been accepted by a fuzzbot
                # and once when the result comes back and has been inserted into the DB.
                # Serial prodclients (that need to know the result) need to wait for the
                # delayed result, general prodclients can send their next test as soon as
                # they get the receipt (which is faster). All prodclients should ignore
                # one of the acks, otherwise they'll flood the queue.
                # Create a delivery receipt, so we can let the prodclient know
                # once this test has been sent to the fuzzbots
                receipt=EventMachine::DefaultDeferrable.new
                receipt.callback do
                    send_ack(msg.ack_id)
                end
                # Create a callback, so we can let the prodclient know once this
                # result is in the database.
                dr=EventMachine::DefaultDeferrable.new
                dr.callback do |result, db_id|
                    send_ack( msg.ack_id, 'result'=>result, 'db_id'=>db_id)
                end
                @delayed_results[server_id]=dr
                # We're passing this test through without verifying
                # the CRC, that's done at the fuzzclient.
                msg_hash={
                    'verb'=>'deliver',
                    'data'=>msg.data,
                    'server_id'=>server_id,
                    'producer_ack_id'=>msg.ack_id,
                    'crc32'=>msg.crc32
                }
                if self.class.queue_shedding
                    # queue this until the DB queue is under control.
                    @tc_queue[msg.queue] << [msg_hash, receipt]
                else
                    if waiting=@fuzzclient_queue[msg.queue].shift
                        waiting.succeed msg_hash, receipt
                    else
                        @tc_queue[msg.queue] << [msg_hash, receipt]
                    end
                end
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
    end
end
