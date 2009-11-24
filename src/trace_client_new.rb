require 'rubygems'
require 'eventmachine'
require 'fileutils'
require 'base64'
require 'zlib'
require 'socket'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/objhax'


# This class is a generic class that can be inherited by task specific traceclients, to 
# do most of the work. It speaks my own Metafuzz protocol which is pretty much JSON
# serialized hashes, containing a verb and other parameters.
#
# The idea here is that we receive an original file and a mutated file, and we trace
# the two files, and push the results to a DB. At this stage we're going to be using an
# external app to do the heavy lifting for the tracing.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class TraceClient < HarnessComponent

    VERSION="2.2.0"
    COMPONENT="TraceClient"
    DEFAULT_CONFIG={
        'server_ip'=>"127.0.0.1",
        'server_port'=>10002,
        'work_dir'=>File.expand_path('C:/traceclient'),
        'poll_interval'=>60,
    }

    def post_init
        @template_cache=self.class.lookup[:template_cache]
    end

    # User should overload this function.
    def trace( crashfile, template )
    end

    # Protocol Receive functions

    def handle_ack_msg( msg )
        stored_msg_hsh=super
        if stored_msg_hsh['verb']=='template_request'
            template_hash=stored_msg_hsh['template_hash']
            decoded_template=Base64::decode64( msg.template )
            if DigestMD5::hexdigest( decoded_template )==template_hash
                @template_cache[template_hash]=decoded_template
            end
        end
        start_idle_loop( 'verb'=>'client_ready' )
    end

    def handle_trace( msg )
        template_hash, encoded_crashfile, db_id=msg.template_hash, msg.crashfile, msg.db_id
        if template=@template_cache[template_hash]
            crashfile=Base64::decode64( encoded_crashfile )
            if Zlib.crc32(crashfile)==msg.crc32
                begin
                    trace( crashfile, template)
                    send_ack( msg.ack_id )
                rescue
                    EventMachine::stop_event_loop
                    raise RuntimeError, "#{COMPONENT}: Fatal error. Dying #{$!}"
                end
            else
                send_ack( msg.ack_id, 'status'=>'error' )
            end
            start_idle_loop( 'verb'=>'client_ready' )
        else
            send_message( 'verb'=>'template_request', 'template_hash'=>template_hash )
        end
    end

    def receive_data( data )
        cancel_idle_loop
        super
    end

    def post_init
        start_idle_loop( 'verb'=>'client_ready' )
    end
end
