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
module FuzzServerConnection

    Unanswered=[]
    def self.unanswered
        Unanswered
    end

    def initialize( parent_klass )
        @server_klass=parent_klass
    end
    
    def send_message( msg_hash )
        self.reconnect(@server_klass.fuzzserver_ip,@server_klass.fuzzserver_port) if self.error?
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(@server_klass.poll_interval)
        waiter.errback do
            @server_klass.unanswered.delete waiter
            puts "Analysis/FSConn: Timed out sending #{msg_hash['verb']}. Retrying."
            send_message( msg_hash )
        end
        @server_klass.unanswered << waiter
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
                'verb'=>
                # ....
            }
            @server_klass.queue[:untraced] << msg_hash
        end
    end

    def handle_new_template( msg )
        raw_template=Base64::decode64( msg.template )
        template_hash=Digest::MD5.hexdigest( raw_template )
        if template_hash==msg.template_hash
            @server_klass.template_cache[template_hash]=raw_template
            @server_klass.db.add_template raw_template, template_hash
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
            db_id=@server_klass.db.add_result(
                result_string,
                crash_data,
                crash_file,
                template_hash
            )
            #Let's get the DB working first...
            #send_to_tracebot( crashfile, template_hash, db_id)
        else
            db_id=@server_klass.db.add_result result_string
        end
        send_ack_result( server_id, db_id, result_string )
        send_db_ready
    end

    def post_init
        @handler=NetStringTokenizer.new
        puts "Analysis/FSConn: Trying to connect to #{@server_klass.fuzzserver_ip} : #{@server_klass.fuzzserver_port}" 
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

