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

# Handle connections from the tracebots in this class, as a server.
# the connection out to the FuzzServer as a client is handled in the 
# FuzzServerConnection class, but is set up with the same config, so
# it can access callback queues, the DB object and so on.
class AnalysisServer < EventMachine::Connection

    VERSION="2.2.0"
    COMPONENT="AnalysisServer"
    DEFAULT_CONFIG={
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

    def self.setup( config_hsh )
        puts "Connecting to DB at #{db_url}..."
        begin
            @db=MetafuzzDB::ResultDB.new( db_url, db_username, db_password )
        rescue
            puts $!
            EM::stop_event_loop
        end
        config_hsh=config_hsh.merge('db'=>@db)
        super
        puts "Connecting out to FuzzServer at #{fuzzserver_ip}..."
        begin
            FuzzServerConnection.setup @config
            EM::connect( fuzzserver_ip, fuzzserver_port, FuzzServerConnection )
        rescue
            raise $!
        end
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
end
