require 'rubygems'
require 'eventmachine'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/result_tracker'
require 'objhax'

# This class is a combination DB / analysis server. It connects out to a fuzzserver, to
# receive results and put them in the result database, and then also acts as a server for
# a group of trace clients that will do extra runtracing and analysis on any crashes.
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

module FuzzServerConnection

    Unanswered=[]
    def self.unanswered
        Unanswered
    end

    def initialize( parent )
        @main_server=parent
    end
    
    def send_message( msg_hash )
        self.reconnect(@main_server.fuzzserver_ip,@main_server.fuzzserver_port) if self.error?
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(@main_server.poll_interval)
        waiter.errback do
            @main_server.unanswered.delete waiter
            puts "Analysis/FSConn: Timed out sending #{msg_hash['verb']}. Retrying."
            send_message( msg_hash )
        end
        @main_server.unanswered << waiter
    end

    def send_db_ready
        send_message('verb'=>'db_ready')
    end

    def send_ack_result( server_id, db_id, result_string )
        send_message(
            'verb'=>'db_ack_result',
            'db_id'=>db_id,
            'server_id'=>server_id,
            'status'=>result_string
        )
    end

    def send_ack_template( template_hash )
        send_message(
            'verb'=>'db_ack_template',
            'template_hash'=>template_hash
        )
    end

    def send_to_tracebot( crashfile, template_hash )
        # get the full template
        if tracebot=@main_server.queue[:tracebots].shift
            tracebot.succeed( crashfile, template, db_id )
        else
            msg.hash={
                'verb'=>
                # ....
            }
            @main_server.queue[:untraced] << msg_hash
        end
    end

    def handle_new_template( msg )
        raw_template=Base64::decode64( msg.template )
        template_hash=Digest::MD5.hexdigest( raw_template )
        if template_hash==msg.template_hash
            @main_server.template_cache[template_hash]=raw_template
            @main_server.db.add_template raw_template
            send_ack_template( template_hash )
            send_db_ready
        else
            # mismatch. Drop, the fuzzserver will resend
            send_db_ready
        end
    end

    def handle_test_result( msg )
        server_id, template_hash, result_string=msg.id, msg.template_hash, msg.status
        if result_string=='crash'
            crash_file=Base64::decode64( msg.crashfile )
            crash_data=msg.crashdata
            db_id=@main_server.db.add_result(
                result_string,
                crash_data,
                crash_file,
                template_hash
            )
            send_to_tracebot( crashfile, template_hash, db_id)
        else
            db_id=@main_server.db.add_result result_string
        end
        send_ack_result( server_id, db_id, result_string )
        send_db_ready
    end

    def post_init
        @handler=NetStringTokenizer.new
        puts "Analysis/FSConn: Trying to connect to #{@main_server.fuzzserver_ip} : #{@main_server.fuzzserver_port}" 
        send_db_ready
    end

    # FuzzMessage#verb returns a string so self.send activates
    # the corresponding 'handle_' instance method above, 
    # and passes the message itself as a parameter.
    def receive_data(data)
        self.class.unanswered.shift.succeed until self.class.unanswered.empty?
        @handler.parse(data).each {|m| 
            msg=FuzzMessage.new(m)
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

end

class TracePair < EventMachine::DefaultDeferrable
    attr_reader :old_file,:new_file, :crc32,:encoding
    def initialize( old_file, new_file, crc, encoding=nil )
        @data=data
        @crc32=crc
        @old_file=old_file
        @new_file=new_file
        @encoding=encoding
        super()
    end
    alias :get_new_trace :succeed
end

class DelayedResult < EventMachine::DefaultDeferrable
    attr_reader :server_id
    def initialize( server_id )
        @server_id=server_id
        super()
    end
    alias :send_result :succeed
end

# Handle connections from the tracebots in this class, as a server.
# the connection out to the FuzzServer as a client is handled in the 
# FuzzServerConnection module, and is passed a reference to the main Queue
# hash.
class TraceServer < EventMachine::Connection

    Queue=Hash.new {|k,v| v=[]}
    def self.queue
        Queue
    end

    TemplateCache=Hash.new {|k,v| v=false}
    def self.template_cache
        TemplateCache
    end

    def self.setup( config_hsh={})
        default_config={
            'agent_name'=>"ANALYZE-O-TRON",
            'server_ip'=>"0.0.0.0",
            'server_port'=>10002,
            'poll_interval'=>60,
            'work_dir'=>File.expand_path('~/analysisserver')
            'fuzzserver_ip'=>'127.0.0.1'
            'fuzzserver_port'=>10001
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

    def post_init
        @handler=NetStringTokenizer.new
        EM::connect(
            self.class.fuzzserver_ip,
            self.class.fuzzserver_port,
            FuzzServerConnection,
            self.class
        )
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

    def receive_data(data)
        @handler.parse(data).each {|m| 
            msg=FuzzMessage.new(m)
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end

end
