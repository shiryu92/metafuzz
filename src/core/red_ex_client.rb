require 'rubygems'
require 'eventmachine'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/streamdiff'
require 'fileutils'
require 'objhax'
require 'base64'
require 'zlib'

# This is a prototype of a crash reducer. The general idea is that you take a template and a
# crash file and want to reduce the changes by gradually reverting bits until the changed bits
# are few enough to exhaust. Bits that trigger the same crash when reverted to their original
# value 'don't matter', bits that change the crash or cause it not to crash do matter, and
# will be part of the crash exhaustion. Currently 18 bits or less is 'small enough' to fully 
# exhaust.
#
# It uses a Fiber to fit in with the async nature of EventMachine so
# that as results come back the Fiber can just be resumed to create the next output until
# eventually the reduction is finished.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class Reducer < EventMachine::Connection

    def self.setup_fiber
        @reducer=Fiber.new do |coalesced|
            coalesced.each {|stream, diff_hsh|
                diff_hsh.each {|offset,chunk|
                    if chunk[:new_binary].length > 8
                        puts "Trying to reduce #{chunk}..."
                        # left_reverted and right_reverted will hold fragments of
                        # the old_binary, new_binary will get modified by slice!
                        # until it contains just the unreverted bits. At each step, to
                        # send, we can just join left_reverted, new_binary, right_reverted.
                        # At the same time, we build the mask which will be used to create a
                        # generator that enumerates all the bits that matter and masks out
                        # the ones that don't
                        loop do
                            break if StreamDiff::bits_to_enumerate(coalesced) < 19
                            break if chunk[:old_binary].empty?
                            chunk[:left_reverted] << chunk[:old_binary].slice!(0,1)
                            chunk[:new_binary].slice!(0,1)
                            chunk[:mid_mask].slice!(0,1)
                            if (Fiber.yield coalesced)
                                # This bit didn't change the crash, it doesn't matter.
                                chunk[:left_mask] << "0"
                            else
                                # This bit matters
                                chunk[:left_mask] << "1"
                            end
                            break if StreamDiff::bits_to_enumerate(coalesced) < 19
                            break if chunk[:old_binary].empty?
                            chunk[:right_reverted]=chunk[:old_binary].slice!(-1,1)+chunk[:right_reverted]
                            chunk[:new_binary].slice!(-1,1)
                            chunk[:mid_mask].slice!(-1,1)
                            if (Fiber.yield coalesced)
                                chunk[:right_mask]="0" << chunk[:right_mask]
                            else
                                chunk[:right_mask]="1" << chunk[:right_mask]
                            end
                        end
                    end
                    break if StreamDiff::bits_to_enumerate(coalesced) < 19
                }
            }
            raise StopIteration
        end
    end

    def self.setup( config_hsh={})
        default_config={
            'agent_name'=>"PRODCLIENT1",
            'server_ip'=>"127.0.0.1",
            'server_port'=>10001,
            'work_dir'=>File.expand_path('~/prodclient'),
            'poll_interval'=>60,
            'crash_file'=false,
            'template_file'=false
        }
        @config=default_config.merge config_hsh
        unless @config['crash_file'] and @config['template_file']
            raise RuntimeError "Reducer: No files to compare?"
        end
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
                    raise RuntimeError, "Reducer: Couldn't create directory: #{$!}"
                end
            else
                raise RuntimeError, "Reducer: Work directory unavailable. Exiting."
            end
        end
        @idtracker=[]
        @server_waits=[]
        @case_id=0
        @crash_hash=""
        @diffs=StreamDiff::generate_diffs(self.class.template_file, self.class.crash_file)
        self.setup_fiber
        class << self
            attr_accessor 'case_id', 'idtracker', 'server_waits', 'diffs', 'crash_hash', 'reducer'
        end
    end

    def diffs_to_raw( coalesced_hsh )
        StreamDiff::diffs_to_raw(self.class.template_file, coalesced_hsh)
    end

    def lookup_crash_hash( server_id )
        # do DB shiz here
    end

    def send_message( msg_hash )
        self.reconnect(self.class.server_ip,self.class.server_port) if self.error?
        send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
    end

    def send_raw_test( raw_test )
        self.class.case_id+=1
        self.class.idtracker << self.class.case_id
        crc=Zlib.crc32(raw_test)
        begin
            # if the encoding property is not defined fall back
            # to base64 for backwards compatability.
            case self.class.production_generator.encoding
            when 'base64'
                encoded_test=Base64.encode64 raw_test
            else
                # encoding property exists but isn't
                # base64 - expand case statement to
                # add more.
                encoded_test=raw_test
            end
        rescue
            encoded_test=Base64.encode64 raw_test
        end
        send_test_case encoded_test, self.class.case_id, crc
    end

    def send_test_case( tc, case_id, crc )
        # If the generator encoding property is not defined fall back to 
        # base64 for backwards compatability (also see send_raw_test)
        send_message(
            'verb'=>'new_test_case',
            'station_id'=>self.class.agent_name,
            'id'=>case_id,
            'crc32'=>crc,
            'encoding'=>(self.class.production_generator.encoding rescue 'base64'),
            'data'=>tc
        )
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            puts "Reducer: Connection timed out. Retrying ID #{case_id.to_s}"
            send_test_case( tc, case_id, crc )
        end
        self.class.server_waits << waiter
    end

    def send_client_bye
        send_message(
            'verb'=>'client_bye',
            'client_type'=>'production',
            'station_id'=>self.class.agent_name,
            'data'=>""
        )
    end

    def send_client_startup
        puts "Reducer: Trying to connect to #{self.class.server_ip} : #{self.class.server_port}" 
        send_message(
            'verb'=>'client_startup',
            'client_type'=>'production',
            'template'=>false,
            'station_id'=>self.class.agent_name,
            'data'=>""
        )
        waiter=EventMachine::DefaultDeferrable.new
        waiter.timeout(self.class.poll_interval)
        waiter.errback do
            puts "Reducer: Connection timed out. Retrying."
            send_client_startup
        end
        self.class.server_waits << waiter
    end

    # Receive methods...

    def handle_ack_case( msg )
        self.class.idtracker.delete msg.id
    end

    def handle_result( msg )
        self.class.server_waits.shift.succeed until self.class.server_waits.empty?
        result=msg.result
        if self.class.case_id==1
            # If this is the result from the first case then it's
            # the crash caused by the unmodified crash file, which
            # is our 'template' for reduction
            unless result=='crash'
                raise RuntimeError, "Reducer: Crash file didn't crash?"
            end
            self.class.crash_hash=lookup_crash_hash(msg.server_id)
            # Kick off the fiber with the diffs between the unreduced crash and
            # the fuzzing template
            send_raw_test(diffs_to_raw(self.class.reducer.resume(self.class.diffs)))
        else
            begin
                # Was it the same crash, true or false
                unless result=='crash' && (lookup_crash_hash(msg.server_id)==self.class.crash_hash)
                    same_crash=false
                else
                    same_crash=true
                end
                self.class.diffs=(self.class.reducer.resume(same_crash))
                send_raw_test(diffs_to_raw(self.class.diffs))
            rescue StopIteration
                # Reduction is finished.
                send_client_bye
                puts "All done, exiting."
                EventMachine::stop_event_loop
            end
        end
    end

    def handle_server_ready( msg )
        self.class.server_waits.shift.succeed until self.class.server_waits.empty?
        # Can't do anything until the result comes back. Ignore.
    end

    def handle_server_bye( msg )
        # In the current protocol, this isn't used, but may as well
        # leave the handler around, just in case.
        puts "Got server_bye, exiting."
        EventMachine::stop_event_loop
    end

    def method_missing( meth, *args )
        raise RuntimeError, "Unknown Command: #{meth.to_s}!"
    end

    def post_init
        @handler=NetStringTokenizer.new
        puts "Connecting to server"
        send_client_startup
        # Send the crash file unmodified, to get the crash details
        send_raw_test self.class.crash_file
    end

    # FuzzMessage#verb returns a symbol, so self.send activates
    # the corresponding instance method above, and passes the message
    # itself as a parameter.
    def receive_data(data)
        @handler.parse(data).each {|m| 
            msg=FuzzMessage.new(m)
            self.send("handle_"+msg.verb.to_s, msg)
        }
    end
end
