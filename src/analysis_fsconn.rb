# This module acts as a client to the FuzzServer code, it connects in and sends a
# db_ready singal, then waits for results. For crashes that needs to be traced, it
# interacts with the TraceServer via a reference to the parent class, by putting
# data directly onto the queues or firing callbacks.
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

class FuzzServerConnection < HarnessComponent

    VERSION="2.0.0"
    COMPONENT="DB:FSConn"

    def initialize( parent_klass )
        @server_klass=parent_klass
        super()
    end

    # Used for the 'heartbeat' messages that get resent when things
    # are in an idle loop
    def start_idle_loop
        send_once( 'verb'=>'db_ready' )
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(@server_klass.poll_interval)
        waiter.errback do
            Queue[:idle].shift
            puts "#{COMPONENT}: Timed out sending #{msg_hash['verb']}. Retrying."
            start_idle_loop
        end
        Queue[:idle] << waiter
    end

    def cancel_idle_loop
        Queue[:idle].shift.succeed
        raise RuntimeError, "#{COMPONENT}: idle queue not empty?" unless Queue[:idle].empty?
    end

    def send_to_tracebot( crashfile, template_hash )
        return # until this is fully implemented
        if template=@server_klass.template_cache[template_hash]
            # good
        else
            template=@server_klass.db.get_template( template_hash )
        end
        encoded_template=Base64::encode64 template
        encoded_crashfile=Base64::encode64 crashfile
        if tracebot=@server_klass.queue[:tracebots].shift
            tracebot.succeed( encoded_crashfile, encoded_template, db_id )
        else
            msg.hash={
                'verb'=>'new_trace_pair'
            }
            @server_klass.queue[:untraced] << msg_hash
        end
    end

    def handle_new_template( msg )
        raw_template=Base64::decode64( msg.template )
        template_hash=Digest::MD5.hexdigest( raw_template )
        if template_hash==msg.template_hash
            unless @server_klass.template_cache.has_key? template_hash
                @server_klass.template_cache[template_hash]=raw_template
                @server_klass.db.add_template raw_template, template_hash
            end
            send_ack msg.ack_id
            start_idle_loop
        else
            # mismatch. Drop, the fuzzserver will resend
            start_idle_loop
        end
    end

    def handle_test_result( msg )
        template_hash, result_string=msg.template_hash, msg.status
        if result_string=='crash'
            crash_file=Base64::decode64( msg.crashfile )
            crash_data=Base64::decode64( msg.crashdata )
            db_id=@server_klass.db.add_result(
                result_string,
                crash_data,
                crash_file,
                template_hash
            )
            send_to_tracebot( crashfile, template_hash, db_id)
        else
            db_id=@server_klass.db.add_result result_string
        end
        send_ack( msg.ack_id, 'db_id'=>db_id )
        start_idle_loop
    end

    def post_init
        start_idle_loop
    end
end

