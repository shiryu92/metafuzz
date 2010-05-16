require 'rubygems'
require 'eventmachine'
require File.dirname(__FILE__) + '/em_netstring'
require File.dirname(__FILE__) + '/fuzzprotocol'
require File.dirname(__FILE__) + '/result_tracker'
require 'objhax'

# This class is a generic class that can be inherited by task specific fuzzservers, to 
# do most of the work. It speaks my own Metafuzz protocol which is pretty much JSON
# serialized hashes, containing a verb and other parameters.
#
# In the overall structure, this class is the broker between the production clients
# and the fuzz clients. It is single threaded, using the Reactor pattern, to make it
# easier to debug.
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
class TracePair < EventMachine::DefaultDeferrable
  attr_reader :old_file,:new_file, :crc32,:encoding
  def initialize( old_file, new_file, crc, encoding=nil )
    @data=data
    @crc32=crc
    @old_file=old_file
    @new_file=new_file
    @encoding=encoding
    super()
  end
  alias :get_new_trace :succeed
end

class DelayedResult < EventMachine::DefaultDeferrable
  attr_reader :server_id
  def initialize( server_id )
    @server_id=server_id
    super()
  end
  alias :send_result :succeed
end

class TraceServer < EventMachine::Connection

  WaitQueue=[]
  DeliveryQueue=[]
  DelayedResultQueue=[]

  def self.waiting_for_data
    WaitQueue
  end

  def self.delivery_queue
    DeliveryQueue
  end

  def self.delayed_result_queue
    DelayedResultQueue
  end

  def self.setup( config_hsh={})
    default_config={
      'agent_name'=>"SERVER",
      'server_ip'=>"0.0.0.0",
      'server_port'=>10002,
      'work_dir'=>File.expand_path('~/traceserver')
    }
    @config=default_config.merge config_hsh
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
          raise RuntimeError, "ProdctionClient: Couldn't create directory: #{$!}"
        end
      else
        raise RuntimeError, "ProductionClient: Work directory unavailable. Exiting."
      end
    end
    @@server_id=0
    def self.server_id
      @@server_id
    end
  end

  def post_init
    @handler=NetStringTokenizer.new
  end

  def send_msg( msg_hash )
    send_data @handler.pack(FuzzMessage.new(msg_hash).to_s)
  end

  # Users might want to overload this function.
  def handle_result( msg )
    self.class.delayed_result_queue.select {|dr| dr.server_id==msg.id}.each {|dr| 
      dr.send_result(msg.status)
      self.class.delayed_result_queue.delete dr
    }
  end

  # Only comes from traceclients.
  def handle_client_ready( msg )
    unless self.class.delivery_queue.empty?
      id,trace_pair=self.class.delivery_queue.shift
      send_msg('verb'=>'new_trace_pair',
               'encoding'=>trace_pair.encoding,
               'old_file'=>trace_pair.old_file,
               'new_file'=>trace_pair.new_file,
               'id'=>id,
               'crc32'=>trace_pair.crc32
              )
              trace_pair.get_new_trace
    else
      waiter=EventMachine::DefaultDeferrable.new
      waiter.callback do |id, trace_pair|
        send_msg('verb'=>'new_trace_pair',
                 'encoding'=>trace_pair.encoding,
                 'old_file'=>trace_pair.old_file,
                 'new_file'=>trace_pair.new_file,
                 'id'=>id,
                 'crc32'=>trace_pair.crc32
                )
                trace_pair.get_new_trace
      end
      self.class.waiting_for_data << waiter
    end
  end

  def handle_client_startup( msg )
    send_msg('verb'=>'server_ready')
  end

  def handle_new_trace_pair( msg )
    # Try not to accept duplicates
    unless self.class.delivery_queue.any? {|id,trace| trace.crc32==msg.crc32 }
      self.class.server_id+=1
      trace_pair=TracePair.new(msg.old_file, msg.new_file, msg.crc32, msg.encoding)
      trace_pair.callback do
        send_msg('verb'=>'ack_trace', 'id'=>msg.id)
        send_msg('verb'=>'server_ready','server_id'=>self.class.server_id)
      end
      dr=DelayedResult.new(server_id)
      dr.callback do |result|
        send_msg('verb'=>'result','result'=>result,'id'=>msg.id,'server_id'=>server_id)
      end
      self.class.delayed_result_queue << dr
      if waiting=self.class.waiting_for_data.shift
        waiting.succeed(server_id,trace_pair)
      else
        self.class.delivery_queue << [server_id, trace_pair]
      end
    end
  end

  def method_missing( meth, *args )
    raise RuntimeError, "Unknown Command: #{meth.to_s}!"
  end

  def receive_data(data)
    @handler.parse(data).each {|m| 
      msg=FuzzMessage.new(m)
      self.send("handle_"+msg.verb.to_s, msg)
    }
  end

end
