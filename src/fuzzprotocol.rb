require 'objhax'
require 'json'
require 'digest/md5'

# This class just handles the serialization, the mechanics of the protocol itself
# is "defined" in the FuzzClient / FuzzServer implementations. It is very lazy
# which allows the protocol to be changed by simply changing the code at each peer.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

class OutMsg < EventMachine::DefaultDeferrable
    attr_reader :msg_hash
    def initialize( msg_hash )
        @msg_hash=msg_hash
    end
end

class FuzzMessage

    # .new can take a Hash or YAML-dumped Hash, and any symbols not defined 
    # below will also be added as getters and setters, making the protocol
    # self extending if both parties agree.
    def initialize(data)
        if data.class==String
            load_json(data)
        else
            unless data.class==Hash
                raise ArgumentError, "FuzzMessage: .new takes a Hash or a JSON-dumped Hash."
            end
            @msghash=data
        end
        # Set up instance getters and setters for the hash symbols
        @msghash.each {|k,v|
            meta_def String(k) do
                @msghash[k]
            end

            meta_def (String(k)+'=') do |new_val|
                @msghash[k]=new_val
            end
        }
    end

    def to_hash
        @msghash
    end

    def load_json(json_data)
        begin
            decoded=JSON::load(json_data)
            unless decoded.class==Hash
                raise ArgumentError, "FuzzMessage (load_json): JSON data not a Hash!"
            end
            @msghash=decoded
        rescue
            raise ArgumentError, "FuzzMessage (load_json): Bad JSON data."
        end
    end

    def to_s
        @msghash.to_json
    end
end

# This class is used to centralize some common code which is used by all
# the Harness classes, so I can maintain it in one place. It's not exactly
# elegantly separated and abstracted, but at least it's not duplicated
# 5 times.
class HarnessComponent < Eventmachine::Connection

    def self.new_ack_id
        @ack_id||=rand(2**31)
        @ack_id+=1
    end

    Queue=Hash.new {|hash, key| hash[key]=Array.new}
    Lookup=Hash.new {|hash, key| hash[key]=Hash.new}

    def self.setup( config_hsh={})
        @config=DEFAULT_CONFIG.merge config_hsh
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
                    raise RuntimeError, "#{COMPONENT}: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "#{COMPONENT}: Work directory unavailable. Exiting."
            end
        end
    end

    # --- Send functions

    def dump_debug_data( msg_hash )
        begin
            port, ip=Socket.unpack_sockaddr_in( get_peername )
            puts "OUT: #{msg_hash['verb']}:#{msg_hash['ack_id'] rescue ''}  to #{ip}:#{port}"

        rescue
            puts "OUT: #{msg_hash['verb']}, not connected yet."

        end
    end

    def send_once( msg_hash )
        dump_debug_data( msg_hash ) if self.class.debug
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
    end

    def send_message( msg_hash, queue=nil )
        # The idea here is that if we want the message delivered
        # to one specific host, we don't pass a queue and it gets
        # resent. For stuff like tests, we don't care who gets them
        # so we just put them back in the outbound queue if they
        # time out.
        # Don't replace the ack_id if it has one
        msg_hash['ack_id']=msg_hash['ack_id'] || self.class.new_ack_id
        if self.class.server_id
            self.reconnect(self.class.server_id, self.class.server_port) if self.error?
        end
        dump_debug_data( msg_hash ) if self.class.debug
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
        waiter=OutMsg.new msg_hash
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            Lookup[:unanswered].delete(msg_hash['ack_id'])
            print "#{COMPONENT}: Timed out sending #{msg_hash['verb']}#{msg_hash['ack_id'] rescue ''}. "
            if queue
                print "Putting it back on the Queue.\n"
                queue << msg_hash
            else
                print "Resending it.\n"
                send_message msg_hash
            end
        end
        Lookup[:unanswered][msg_hash['ack_id']]=waiter
    end

    def send_ack(ack_id, extra_data={})
        msg_hash={
            'verb'=>'ack_msg',
            'ack_id'=>ack_id,
        }
        msg_hash.merge! extra_data
        dump_debug_data( msg_hash ) if self.class.debug
        # We only send one ack. If the ack gets lost and the sender cares
        # they will resend.
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
    end

    # FuzzMessage#verb returns a string so self.send activates
    # the corresponding 'handle_' instance method above, 
    # and passes the message itself as a parameter.
    def receive_data(data)
        @handler.parse(data).each {|m| 
            msg=FuzzMessage.new(m)
            if self.class.debug
                port, ip=Socket.unpack_sockaddr_in( get_peername )
                puts "IN: #{msg.verb}:#{msg.ack_id rescue ''} from #{ip}:#{port}"
                sleep 1
            end
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

    def initialize
        @handler=NetStringTokenizer.new
        puts "#{COMPONENT} #{VERSION}: Trying to connect to #{self.class.server_ip} : #{self.class.server_port}" 
    rescue
        puts $!
        EventMachine::stop_event_loop
    end
end
