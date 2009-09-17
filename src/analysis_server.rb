require 'rubygems'
require 'eventmachine'
require 'socket'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/metafuzz_db'
require File.dirname(__FILE__) + '/analysis_fsconn'
require File.dirname(__FILE__) + '/objhax'

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
# FuzzServerConnection class, and is passed a reference to this class,
# so it can access the callback queues and the like.
class AnalysisServer < EventMachine::Connection

    Queue=Hash.new {|hash, key| hash[key]=Array.new}
    def self.queue
        Queue
    end

    Lookup=Hash.new {|hash, key| hash[key]=Hash.new}
    def self.lookup
        Lookup
    end

    TemplateCache=Hash.new( false )
    def self.template_cache
        TemplateCache
    end

    def self.setup( config_hsh={})
        default_config={
            'agent_name'=>"ANALYZE-O-TRON",
            'server_ip'=>"0.0.0.0",
            'server_port'=>10002,
            'poll_interval'=>60,
            'debug'=>false,
            'work_dir'=>File.expand_path('~/analysisserver'),
            'db_url'=>'postgres://localhost/metafuzz_resultdb',
            'db_username'=>'postgres',
            'db_password'=>'password',
            'fuzzserver_ip'=>'127.0.0.1',
            'fuzzserver_port'=>10001
        }
        @config=default_config.merge config_hsh
        @config.each {|k,v|
            meta_def k do v end
            meta_def k.to_s+'=' do |new| @config[k]=new end
        }
        unless File.directory? work_dir
            print "Work directory #{work_dir} doesn't exist. Create it? [y/n]: "
            answer=STDIN.gets.chomp
            if answer =~ /^[yY]/
                begin
                    Dir.mkdir(work_dir)
                rescue
                    raise RuntimeError, "ProdctionClient: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "ProductionClient: Work directory unavailable. Exiting."
            end
        end
        puts "Connecting to DB at #{db_url}..."
        @db=MetafuzzDB::ResultDB.new( db_url, db_username, db_password )
        meta_def :db do @db end
        puts "Ok!"
        puts "Connecting out to FuzzServer at #{fuzzserver_ip}..."
        begin
            EM::connect( fuzzserver_ip, fuzzserver_port, FuzzServerConnection, self )
        rescue
            raise $!
        end
        puts "Ok! Setup done."
    end

    def handle_result( msg )
    end

    def handle_client_ready( msg )
    end

    def handle_client_bye( msg )
    end

    def handle_client_startup( msg )
    end
    
    def send_new_trace_pair
    end

    def send_server_ready
    end

    def send_server_bye
    end


    def post_init
        @handler=NetStringTokenizer.new
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