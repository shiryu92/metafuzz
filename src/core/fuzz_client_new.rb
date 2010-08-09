require 'rubygems'
require 'eventmachine'
require 'fileutils'
require 'base64'
require 'digest/md5'
require 'zlib'
require 'socket'
require 'win32api'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/objhax'


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
class FuzzClient < HarnessComponent

    VERSION="3.0.0"
    COMPONENT="FuzzClient"
    DEFAULT_CONFIG={
        'server_ip'=>"127.0.0.1",
        'server_port'=>10001,
        'work_dir'=>File.expand_path('C:/fuzzclient'),
        'poll_interval'=>60,
        'queue_name'=>'bulk'
    }


    def create_tag( raw_crash, opts )
        if RUBY_PLATFORM =~ /mswin|mingw/
            # This leaks the local MAC address, but that's prbably a good thing
            # in case we need to track bad cases to a specific box. It's also faster.
            @uuid_create||=Win32API.new('rpcrt4', 'UuidCreateSequential', 'P', 'L')
            buf=' ' * 16 # will be filled in by the call
            @uuid_create.call( buf )
            uuid=("%x%x-%x-%x-%x-%x%x%x" % buf.unpack('S*')).upcase
        else
            # OSX and linux should have uuidgen...
            uuid=`uuidgen`.chomp.upcase
        end
        digest=Digest::MD5.hexdigest( raw_crash )
        tag=""
        tag << "FUZZBOT_OPTS:#{opts.join(' ')}"
        tag << "FUZZBOT_CRASH_MD5:#{digest}\n"
        tag << "FUZZBOT_CRASH_CRC32:#{Zlib.crc32( raw_crash )}\n"
        tag << "FUZZBOT_CRASH_UUID:#{uuid}\n"
        tag << "FUZZBOT_TIMESTAMP:#{Time.now}\n"
        tag
    end

    # User should overload this function.
    def deliver( data, msg_id, opts=[] )
        # Deliver the test here, return the status and any extended
        # crash data (eg debugger output). Currently, the harness
        # uses 'success', 'fail', 'crash' and 'error'
        ['success', ""]
    end

    # Protocol Receive functions

    def handle_deliver( msg )
        if Zlib.crc32(msg.data)==msg.crc32
            begin
                opts=msg.fuzzbot_options rescue []
                status,crash_details=deliver(msg.data,msg.server_id,opts)
                if status=='crash'
                    our_tag=msg.tag << create_tag( msg.data, opts )
                    send_ack(msg.ack_id, 'status'=>status, 'data'=>crash_details, 'crc32'=>msg.crc32, 'tag'=>tag)
                else
                    send_ack(msg.ack_id, 'status'=>status)
                end
            rescue
                # Don't send an error, because we don't know if this
                # test was bad or the deliver function had a transient
                # failure. (An error will stop the sever from requeueing
                # this test for delivery)
                if self.class.debug
                    warn "#{COMPONENT}: #{$!}"
                end
            end
        else
            # A CRC mismatch is the producer's fault, this test
            # is not recoverable.
            send_ack(msg.ack_id, 'status'=>'error')
        end
        start_idle_loop( 'verb'=>'client_ready', 'queue'=>self.class.queue_name)
    end

    def receive_data( data )
        cancel_idle_loop
        super
    end

    def post_init
        start_idle_loop( 'verb'=>'client_ready', 'queue'=>self.class.queue_name)
    end
end
