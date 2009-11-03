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

    VERSION="2.2.0"
    COMPONENT="DB:FSConn"
    DEFAULT_CONFIG={
        'poll_interval'=>60,
        'debug'=>false,
        'server_ip'=>'127.0.0.1',
        'server_port'=>10001,
        'work_dir'=>File.expand_path('~/analysisserver')
    }

    def post_init
        # We share the template cache and the trace message queue
        # with the AnalysisServer. All we do from here is keep the
        # template cache up to date and write onto the trace_msg_q.
        @trace_msg_q=self.class.parent_klass.queue[:trace_msgs]
        @template_cache=self.class.parent_klass.lookup[:template_cache]
        @db=self.class.db
        start_idle_loop( 'verb'=>'db_ready' )
    end

    def add_to_trace_queue( encoded_crashfile, template_hash, db_id, crc32 )
        return # until this is fully implemented
        msg_hsh={
            'verb'=>'trace',
            'template_hash'=>template_hash,
            'crashfile'=>encoded_crashfile,
            'crc32'=>crc32,
            'db_id'=>db_id
        }
        unless @trace_msg_q.any? {|hsh| hsh['db_id']==db_id}
            @trace_msg_q << msg_hash
        end
    end

    def handle_new_template( msg )
        raw_template=Base64::decode64( msg.template )
        template_hash=Digest::MD5.hexdigest( raw_template )
        if template_hash==msg.template_hash
            unless @template_cache.has_key? template_hash
                @template_cache[template_hash]=raw_template
                @db.add_template raw_template, template_hash
            end
            send_ack msg.ack_id
        else
            # mismatch. Drop, the fuzzserver will resend
            if self.class.debug
                puts "#{COMPONENT}: MD5 mismatch in #{__method__}, ignoring."
            end
        end
        start_idle_loop( 'verb'=>'db_ready' )
    end

    def handle_test_result( msg )
        template_hash, result_string=msg.template_hash, msg.status
        if result_string=='crash'
            crash_file=Base64::decode64( msg.crashfile )
            if Zlib.crc32(crash_file)==msg.crc32
                crash_data=Base64::decode64( msg.crashdata )
                db_id=@db.add_result(
                    result_string,
                    crash_data,
                    crash_file,
                    template_hash
                )
                add_to_trace_queue( msg.crashfile, template_hash, db_id, crc32)
                send_ack( msg.ack_id, 'db_id'=>db_id )
            end
        else
            db_id=@db.add_result result_string
            send_ack( msg.ack_id, 'db_id'=>db_id )
        end
        start_idle_loop( 'verb'=>'db_ready' )
    end

    def receive_data( data )
        cancel_idle_loop
        super
    end
end

