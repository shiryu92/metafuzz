require 'rubygems'
require 'eventmachine'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/result_tracker'
require 'objhax'
require 'base64'
require 'zlib'
require 'digest/md5'

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

    # --- Class stuff.

    Queue=Hash.new {|k,v| v=[]}
    def self.queue
        Queue
    end

    Lookup=Hash.new {|k,v| v={}}
    def self.lookup
        Lookup
    end

    def self.next_server_id
        @@server_id||=0
        @@server_id+=1
    end

    VERSION="1.2.0"
    def self.setup( config_hsh={})
        default_config={
            'agent_name'=>"SERVER",
            'server_ip'=>"0.0.0.0",
            'server_port'=>10001,
            'poll_interval'=>60,
            'work_dir'=>File.expand_path('~/fuzzserver'),
            'database_filename'=>"/dev/shm/metafuzz.db"
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
        @handler=NetStringTokenizer.new
    end

    # --- Send functions

    def send_message( msg_hash )
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
    end

    def db_send( msg_hash, unique_tag )
        # Don't add duplicates to the outbound db queue.
        unless self.class.queue[:db_messages].any? {|hsh| msg_hash==hsh}
            # If we have a ready DB, send the message, otherwise
            # put a callback in the queue.
            if dbconn=self.class.queue[:dbconns].shift
                dbconn.succeed msg_hash
                # Make sure this gets acked by the DB
                not_acked=EventMachine::DefaultDeferrable.new
                not_acked.timeout=self.class.poll_interval
                not_acked.errback do
                    self.class.lookup[:unanswered].delete unique_tag
                    puts "Fuzzserver: DB didn't respond to #{msg_hash['verb']}. Retrying."
                    db_send msg_hash
                end
                self.class.lookup[:unanswered][unique_tag]=not_acked
            else
                self.class.queue[:db_messages] << msg_hash
            end
        end
        if (len=self.class.queue[:db_messages].length) > 50
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
        db_send msg_hash, tag=server_id
    end

    def send_template_to_db( template, template_hash )
        msg_hash={
            'verb'=>'new_template',
            'encoding'=>'base64',
            'template'=>Base64::encode64( template ),
            'template_hash'=>template_hash
        }
        db_send msg_hash, tag=template_hash
    end

    # --- Receive functions

    def handle_db_ready( msg )
        if self.class.queue[:db_messages].empty?
            # if there are no messages waiting to be sent, add this ready DB
            # to a queue, so we can use it to send a message when required.
            dbconn=EventMachine::DefaultDeferrable.new
            dbconn.callback do |msg_hash|
                send_message msh_hash
            end
            self.class.queue[:dbconns] << dbconn
        else
            send_message self.class.queue[:db_messages].shift
        end
    end

    def handle_db_ack_result( msg )
        server_id, db_id, result_status=msg.server_id, msg.db_id, msg.status
        dr=self.class.lookup[:delayed_results].delete server_id
        dr.send_result(result_status, db_id)
        self.class.lookup[:unanswered].delete(server_id).succeed
    end

    def handle_db_ack_template( msg )
        self.class.lookup[:unanswered].delete(msg.template_hash).succeed
    end

    # Users might want to overload this function.
    def handle_result( msg )
        server_id,result_status,crashdata,crashfile=msg.server_id, msg.status, msg.data, msg.crashfile
        if result_status=='crash'
            detail_path=File.join(self.class.work_dir,"detail-#{server_id}.txt")
            crashfile_path=File.join(self.class.work_dir,"crash-#{server_id}")
            File.open(detail_path, "wb+") {|io| io.write(crashdata)}
            File.open(crashfile_path, "wb+") {|io| io.write(crashfile)}
        end
        template_hash=self.class.lookup[:template_tracker].delete server_id
        send_result_to_db(server_id, template_hash, result_status, crashdata, crashfile)
    end

    # Only comes from fuzzclients.
    def handle_client_ready( msg )
        unless self.class.queue[:test_cases].empty?
            server_id,test_case=self.class.queue[:test_cases].shift
            send_message(
                'verb'=>'deliver',
                'encoding'=>test_case.encoding,
                'data'=>test_case.data,
                'server_id'=>server_id,
                'crc32'=>test_case.crc32
            )
            test_case.get_new_case
        else
            waiter=EventMachine::DefaultDeferrable.new
            waiter.callback do |server_id, test_case|
                send_message(
                    'verb'=>'deliver',
                    'encoding'=>test_case.encoding,
                    'data'=>test_case.data,
                    'server_id'=>server_id,
                    'crc32'=>test_case.crc32
                )
                test_case.get_new_case
            end
            self.class.queue[:fuzzclients] << waiter
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
                    send_template_to_db(template, template_hash)
                    self.class.lookup[:templates][template_hash]=true
                end
            rescue
                raise RuntimeError, "FuzzServer: Prodclient template error: #{$!}"
            end
        end
        send_message('verb'=>'server_ready')
    end

    def handle_new_test_case( msg )
        unless self.class.queue[:test_cases].any? {|id,tc| tc.crc32==msg.crc32 }
            if self.class.lookup[:templates][msg.template_hash]
                send_message('verb'=>'ack_case', 'id'=>msg.id)
                server_id=self.class.next_server_id
                self.class.lookup[:template_tracker][server_id]=msg.template_hash
                # Prepare this test case for delivery
                test_case=TestCase.new(msg.data, msg.crc32, msg.encoding)
                test_case.callback do
                    send_message('verb'=>'server_ready')
                end
                if waiting=self.class.queue[:fuzzclients].shift
                    waiting.succeed(server_id,test_case)
                else
                    self.class.queue[:test_cases] << [server_id, test_case]
                end
                # Create a callback, so we can let the prodclient know once this
                # result is in the database.
                dr=DelayedResult.new
                dr.callback do |result, db_id|
                    send_message('verb'=>'result','result'=>result,'id'=>msg.id,'db_id'=>db_id)
                end
                self.class.lookup[:delayed_results][server_id]=dr
            else
                raise RuntimeError, "FuzzServer: New case, but no template"
            end
        end
    end

    def receive_data(data)
        @handler.parse(data).each {|m| 
            msg=FuzzMessage.new(m)
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

end
