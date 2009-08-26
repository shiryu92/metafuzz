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
class TestCase < EventMachine::DefaultDeferrable
	attr_reader :data,:crc32,:encoding
	def initialize( data, crc, encoding=nil )
		@data=data
                @crc32=crc
		@encoding=encoding
		super()
	end
	alias :get_new_case :succeed
end

class DelayedResult < EventMachine::DefaultDeferrable
	attr_reader :server_id
	def initialize( server_id )
            @server_id=server_id
		super()
	end
	alias :send_result :succeed
end

class FuzzServer < EventMachine::Connection

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
			'server_port'=>10001,
			'work_dir'=>File.expand_path('~/fuzzserver'),
			'database_filename'=>"/dev/shm/metafuzz.db"
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
		# Class instance variables, shared across subclass instances
		# but not between different subclasses.
		@@result_tracker=ResultTracker.new(self.database_filename)
		def self.result_tracker
			@@result_tracker
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
		result_id,result_status,crashdata,crashfile=msg.id, msg.status, msg.data, msg.crashfile
		if result_status=='crash'
			detail_path=File.join(self.class.work_dir,"detail-#{result_id}.txt")
			crashfile_path=File.join(self.class.work_dir,"crash-#{result_id}")
			File.open(detail_path, "wb+") {|io| io.write(crashdata)}
			File.open(crashfile_path, "wb+") {|io| io.write(crashfile)}
		end
		self.class.result_tracker.add_result(Integer(result_id),result_status,detail_path||=nil,crashfile_path||=nil)
                self.class.delayed_result_queue.select {|dr| dr.server_id==msg.id}.each {|dr| 
                        dr.send_result(result_status)
                        self.class.delayed_result_queue.delete dr
                }
	end

	# Only comes from fuzzclients.
	def handle_client_ready( msg )
		unless self.class.delivery_queue.empty?
			id,test_case=self.class.delivery_queue.shift
			send_msg('verb'=>'deliver','encoding'=>test_case.encoding,'data'=>test_case.data,'id'=>id,'crc32'=>test_case.crc32)
			test_case.get_new_case
		else
			waiter=EventMachine::DefaultDeferrable.new
			waiter.callback do |id, test_case|
				send_msg('verb'=>'deliver','encoding'=>test_case.encoding,'data'=>test_case.data,'id'=>id,'crc32'=>test_case.crc32)
				test_case.get_new_case
			end
			self.class.waiting_for_data << waiter
		end
	end

	def handle_client_startup( msg )
		send_msg('verb'=>'server_ready')
	end

	def handle_new_test_case( msg )
		unless self.class.delivery_queue.any? {|id,tc| tc.crc32==msg.crc32 }
			server_id=self.class.result_tracker.check_out
			test_case=TestCase.new(msg.data, msg.crc32, msg.encoding)
			test_case.callback do
				send_msg('verb'=>'ack_case', 'id'=>msg.id)
				send_msg('verb'=>'server_ready','server_id'=>server_id)
			end
                        dr=DelayedResult.new(server_id)
                        dr.callback do |result|
                            send_msg('verb'=>'result','result'=>result,'id'=>msg.id,'server_id'=>server_id)
                        end
                        self.class.delayed_result_queue << dr
			if waiting=self.class.waiting_for_data.shift
				waiting.succeed(server_id,test_case)
			else
				self.class.delivery_queue << [server_id, test_case]
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
