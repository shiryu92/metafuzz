require 'rubygems'
require 'eventmachine'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require 'fileutils'
require 'objhax'
require 'base64'
require 'zlib'

# This class is a generic class that can be inherited by task specific production clients, to 
# do most of the work. It speaks my own Metafuzz protocol which is pretty much JSON
# serialized hashes, containing a verb and other parameters.
#
# In the overall structure, one or more of these will feed test cases to the fuzz server.
# In a more complicated implementation it would also be able to adapt, based on the results.
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
class TraceProducer < EventMachine::Connection

  def self.setup( config_hsh={})
    default_config={
      'agent_name'=>"TRACEPRODUCER",
      'server_ip'=>"127.0.0.1",
      'server_port'=>10002,
      'work_dir'=>File.expand_path('~/prodclient'),
      'poll_interval'=>60,
      'work_fiber'=>false, # Needs to be set by the calling code!
      'encoding'=>'base64'
    }
    @config=default_config.merge config_hsh
    @config.each {|k,v|
      meta_def k do v end
      meta_def k.to_s+'=' do |new| @config[k]=new end
    }
    unless self.class.work_fiber
      raise RuntimeError, "TraceProducer: No work fiber defined."
    end
    unless File.directory? @config['work_dir']
      print "Work directory #{@config['work_dir']} doesn't exist. Create it? [y/n]: "
      answer=STDIN.gets.chomp
      if answer =~ /^[yY]/
        begin
          Dir.mkdir(@config['work_dir'])
        rescue
          raise RuntimeError, "TraceProducer: Couldn't create directory: #{$!}"
        end
      else
        raise RuntimeError, "TraceProducer: Work directory unavailable. Exiting."
      end
    end
    @idtracker=[]
    @server_waits=[]
    @case_id=0
    class << self
      attr_accessor 'case_id', 'idtracker', 'server_waits'
    end
  end

  def send_message( msg_hash )
    self.reconnect(self.class.server_ip,self.class.server_port) if self.error?
    send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
  end

  def send_new_trace_pair( old_file, new_file, case_id, crc )
    # If the generator encoding property is not defined fall back to 
    # base64 for backwards compatability (also see handle_server_ready)
    send_message(
      'verb'=>'new_trace_pair',
      'station_id'=>self.class.agent_name,
      'id'=>case_id,
      'crc32'=>crc,
      'encoding'=>'base64',
      'old_file'=>old_file,
      'new_file'=>new_file
    )
    waiter=EventMachine::DefaultDeferrable.new
    waiter.timeout(self.class.poll_interval)
    waiter.errback do
      puts "ProdClient: Connection timed out. Retrying ID #{case_id.to_s}"
      send_message(
        'verb'=>'new_trace_pair',
        'station_id'=>self.class.agent_name,
        'id'=>case_id,
        'crc32'=>crc,
        'encoding'=>'base64',
        'old_file'=>old_file,
        'new_file'=>new_file
      )
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
    puts "ProdClient: Trying to connect to #{self.class.server_ip} : #{self.class.server_port}" 
    send_message(
      'verb'=>'client_startup',
      'client_type'=>'trace_production',
      'template'=>false,
      'station_id'=>self.class.agent_name,
      'data'=>""
    )
    waiter=EventMachine::DefaultDeferrable.new
    waiter.timeout(self.class.poll_interval)
    waiter.errback do
      puts "ProdClient: Connection timed out. Retrying."
      send_client_startup
    end
    self.class.server_waits << waiter
  end

  # Receive methods...

  def handle_ack_case( msg )
    self.class.idtracker.delete msg.id
  end

  def handle_result( msg )
    # ignore, by default
  end

  def handle_server_ready( msg )
    self.class.server_waits.shift.succeed until self.class.server_waits.empty?
    begin
      self.class.case_id+=1
      self.class.idtracker << self.class.case_id
      old_file, new_file=self.class.work_fiber.resume
      crc=Zlib.crc32(old_file+new_file)
      begin
        case self.class.encoding
        when 'base64'
          encoded_old=Base64.encode64 old_file
          encoded_new=Base64.encode64 new_file
        else
          # encoding property exists but isn't
          # base64 - expand case statement to
          # add more.
          encoded_old=old_file
          encoded_new=new_file
        end
      rescue
        # if the encoding property is not defined fall back
        # to base64 for backwards compatability.
        encoded_old=Base64.encode64 old_file
        encoded_new=Base64.encode64 new_file
      end
      send_new_trace_pair encoded_old, encoded_new, self.class.case_id, crc
    rescue StopIteration
      send_client_bye
      puts "All done, exiting."
      EventMachine::stop_event_loop
    end
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
