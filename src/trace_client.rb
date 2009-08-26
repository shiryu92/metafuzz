require 'rubygems'
require 'eventmachine'
require 'em_netstring'
require 'traceprotocol'
require 'fileutils'
require 'objhax'
require 'base64'
require 'zlib'


# Quick and dirty cilent to distribute tracing work. Uses the same general 
# structure as the fuzz client but invokes an external python script to 
# do the actual trace, for now, until there is a usable Ruby debugger 
# framework for Windows.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class TraceClient < EventMachine::Connection

  VERSION="1.0.0"
  def self.setup( config_hsh={})
    default_config={
      'agent_name'=>"TRACER",
      'server_ip'=>"127.0.0.1",
      'server_port'=>10002,
      'work_dir'=>File.expand_path('C:/traceclient'),
      'poll_interval'=>60,
      'paranoid'=>false
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
          raise RuntimeError, "TraceClient: Couldn't create directory: #{$!}"
        end
      else
        raise RuntimeError, "TraceClient: Work directory unavailable. Exiting."
      end
    end
    @unanswered=[]
    class << self
      attr_reader :unanswered
    end
  end

  def post_init
    @handler=NetStringTokenizer.new
    puts "TraceClient#{VERSION}: Starting up..."
    send_client_startup
  end

  def trace( old_file, new_file )
    #invoke python tracer here
    # results will get sent out of band to the DB
    'success'
  end

  # Protocol Send functions

  def send_message( msg_hash )
    self.reconnect(self.class.server_ip,self.class.server_port) if self.error?
    send_data @handler.pack(traceMessage.new(msg_hash))
  end

  def send_client_bye
    send_message(
      'verb'=>'client_bye',
      'station_id'=>self.class.agent_name,
      'data'=>"")
  end

  def send_client_startup
    send_message(
      'verb'=>'client_startup',
      'station_id'=>self.class.agent_name,
      'client_type'=>'trace',
      'data'=>"")
      waiter=EventMachine::DefaultDeferrable.new
      waiter.timeout(self.class.poll_interval)
      waiter.errback do
        puts "traceclient: Initial connection timed out. Retrying."
        send_client_startup
      end
      self.class.unanswered << waiter
  end

  def send_client_ready
    send_message(
      'verb'=>'client_ready',
      'station_id'=>self.class.agent_name,
      'data'=>"")
      waiter=EventMachine::DefaultDeferrable.new
      waiter.timeout(self.class.poll_interval)
      waiter.errback do
        puts "traceclient: Connection timed out. Retrying."
        send_client_ready
      end
      self.class.unanswered << waiter
  end

  def send_result(id, status)
    send_message(
      'verb'=>'result',
      'station_id'=>self.class.agent_name,
      'id'=>id,
      'status'=>status
    )
  end

  # Protocol Receive functions

  def handle_new_trace_pair( msg )
    self.class.unanswered.shift.succeed until self.class.unanswered.empty?
    case msg.encoding
    when 'base64'
      old_file=Base64::decode64(msg.old_file)
      new_file=Base64::decode64(msg.new_file)
    else
      old_file=msg.old_file
      new_file=msg.new_file
    end
    if self.class.paranoid
      unless Zlib.crc32(old_file+new_file)==msg.crc32
        raise RuntimeError, "traceclient: data corruption, mismatched CRC32."
      end
    end
    begin
      status=trace(old_file, new_file)
    rescue
      status='error'
      EventMachine::stop_event_loop
      raise RuntimeError, "traceclient: Fatal error. Dying #{$!}"
    end
    send_result msg.id, status
    send_client_ready
  end

  def handle_server_ready( msg )
    self.class.unanswered.shift.succeed until self.class.unanswered.empty?
    send_client_ready
  end

  def handle_server_bye( msg )
    puts "TraceClient: Server is finished."
    send_client_bye
    EventMachine::stop_event_loop
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
