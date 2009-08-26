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
    attr_reader :data,:crc32,:template_hash,:encoding
    def initialize( data, crc, template_hash, encoding=nil )
        @data=data
        @crc32=crc
        @template_hash=template_hash
        @encoding=encoding
        super()
    end
    alias :get_new_case :succeed
end

class DelayedResult < EventMachine::DefaultDeferrable
    attr_reader :server_id
    def initialize( server_id )
        @server_id=server_id
        super()
    end
    alias :send_result :succeed
end

class FuzzServer < EventMachine::Connection

    Queues={}
    Queues[:fuzzclients]=[]
    Queues[:test_cases]=[]
    Queues[:delayed_result]=[]
    Queues[:dbconns]=[]
    Queues[:db_messages]=[]
    def self.queue
        Queues
    end
    Templates=Hash.new(false)
    def self.templates
        Templates
    end
    VERSION="1.2.0"
    def self.setup( config_hsh={})
        default_config={
            'agent_name'=>"SERVER",
            'server_ip'=>"0.0.0.0",
            'server_port'=>10001,
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
        # Class instance variables, shared across subclass instances
        # but not between different subclasses.
        @@server_id=0
    end

    def post_init
        @handler=NetStringTokenizer.new
    end

    # --- Send functions

    def send_msg( msg_hash )
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
    end

    def send_result_to_db( server_id, status, crashdata, crashfile )
        msg_hash={
            'verb'=>'result',
            'id'=>server_id,
            'status'=>status,
            'encoding'=>'base64',
            'crashdata'=>crashdata,
            'crashfile'=>crashfile
        }
        if dbconn=self.class.queue[:dbconns].shift
            dbconn.succeed msg_hash
        else
            self.class.queue[:db_messages] << msg_hash
        end
    end

    def send_template_to_db( template )
        msg_hash={
            'verb'=>'new_template'
            'encoding'=>'base64'
            'template'=>Base64::encode64( template )
            'crc32'=>Zlib.crc32( template )
        }
        if dbconn=self.class.queue[:dbconns].shift
            dbconn.succeed msg_hash
        else
            self.class.queue[:db_messages] << msg_hash
        end
    end

    # --- Receive functions

    def handle_db_ready( msg )
        if self.class.queue[:db_messages].empty?
            dbconn=EventMachine::DefaultDeferrable.new
            dbconn.callback do |msg_hash|
                send_msg msh_hash
            end
            self.class.queue[:dbconns] << dbconn
        else
            send_msg self.class.queue[:db_messages].shift
        end
    end

    def handle_db_ack_result( msg )
        server_id=msg.id
        db_id=msg.db_id
        result_status=msg.status
        self.class.queue[:delayed_result].select {|dr| dr.server_id==server_id}.each {|dr| 
            dr.send_result(result_status, db_id)
            self.class.queue[:delayed_result].delete dr
        }
    end

    # Users might want to overload this function.
    def handle_result( msg )
        server_id,result_status,crashdata,crashfile=msg.id, msg.status, msg.data, msg.crashfile
        if result_status=='crash'
            detail_path=File.join(self.class.work_dir,"detail-#{server_id}.txt")
            crashfile_path=File.join(self.class.work_dir,"crash-#{server_id}")
            File.open(detail_path, "wb+") {|io| io.write(crashdata)}
            File.open(crashfile_path, "wb+") {|io| io.write(crashfile)}
        end
        send_result_to_db(server_id, result_status, crashdata, crashfile)
    end

    # Only comes from fuzzclients.
    def handle_client_ready( msg )
        unless self.class.queue[:test_cases].empty?
            server_id,test_case=self.class.queue[:test_cases].shift
            send_msg('verb'=>'deliver','encoding'=>test_case.encoding,'data'=>test_case.data,'id'=>server_id,'crc32'=>test_case.crc32)
            test_case.get_new_case
        else
            waiter=EventMachine::DefaultDeferrable.new
            waiter.callback do |server_id, test_case|
                send_msg('verb'=>'deliver','encoding'=>test_case.encoding,'data'=>test_case.data,'id'=>server_id,'crc32'=>test_case.crc32)
                test_case.get_new_case
            end
            self.class.queue[:fuzzclients] << waiter
        end
    end

    def handle_client_startup( msg )
        if msg.client_type=='production'
            begin
                raw_template=msg.template
                case msg.encoding
                when 'none'
                    template=msg.data
                else
                    template=Base64::decode64(msg.data)
                end
                template_hash=Digest::MD5.hexdigest(template)
                self.class.templates[template_hash]=template
                send_template_to_db(template)
            rescue
                raise RuntimeError, "FuzzServer: Prodclient tried to start without a template."
            end
        end
        send_msg('verb'=>'server_ready')
    end

    def handle_new_test_case( msg )
        unless self.class.queue[:test_cases].any? {|id,tc| tc.crc32==msg.crc32 }
            if self.class.templates[msg.template_hash]
                @@server_id+=1
                server_id=@@server_id
                test_case=TestCase.new(msg.data, msg.crc32, msg.template_hash, msg.encoding)
                test_case.callback do
                    send_msg('verb'=>'ack_case', 'id'=>msg.id)
                    send_msg('verb'=>'server_ready','server_id'=>server_id)
                end
                dr=DelayedResult.new(server_id)
                dr.callback do |result, db_id|
                    send_msg('verb'=>'result','result'=>result,'id'=>msg.id,'db_id'=>db_id)
                end
                self.class.queue[:delayed_result] << dr
                if waiting=self.class.queue[:fuzzclients].shift
                    waiting.succeed(server_id,test_case)
                else
                    self.class.queue[:test_cases] << [server_id, test_case]
                end
            else
                raise RuntimeError, "FuzzServer: Template error in new test: $!"
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
