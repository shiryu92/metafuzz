require 'rubygems'
require 'eventmachine'
require 'fileutils'
require 'base64'
require 'zlib'
require 'socket'
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

    VERSION="2.2.0"
    COMPONENT="FuzzClient"
    DEFAULT_CONFIG={
        'server_ip'=>"127.0.0.1",
        'server_port'=>10001,
        'work_dir'=>File.expand_path('C:/fuzzclient'),
        'poll_interval'=>5,
        'queue_name'=>'bulk'
    }

    # User should overload this function.
    def deliver( data, msg_id )
        # Deliver the test here, return the status and any extended
        # crash data (eg debugger output). Currently, the harness
        # uses 'success', 'fail', 'crash' and 'error'
        ['success', ""]
    ensure
        data=nil
    end

    # Protocol Receive functions

    def handle_deliver( msg )
        fuzzdata=Base64::decode64(msg.data)
        if Zlib.crc32(fuzzdata)==msg.crc32
            begin
                status,crash_details=deliver(fuzzdata,msg.server_id)
                fuzzdata=nil
                if status=='crash'
                    encoded_details=Base64::encode64(crash_details)
                    send_ack(msg.ack_id, 'status'=>status, 'data'=>encoded_details)
                else
                    send_ack(msg.ack_id, 'status'=>status)
                end
            rescue
                # Don't send an error, because we don't know if this
                # test was bad or the deliver function had a transient
                # failure. (An error will stop the sever from requeueing
                # this test for delivery)
                if self.class.debug
                    puts "#{COMPONENT}: #{$!}"
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
