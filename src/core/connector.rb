#require 'objhax'
require 'thread'

#The Connector class is a generic interface to sending and receiving
#data from a target. A new connector must be instantiated using a 
#protocol module, follwed by the arguments required by the module. eg:
#
# tcp=Connector.new(CONN_TCP, 'www.google.com', 80)
# gre=Connector.new(CONN_RAWIP, '10.0.0.1', 47) # GRE is IP Protocol 47
# ike=Connector.new(CONN_UDP, '10.0.0.1', 500, 500) #specifies optional source port
#
#The Connector object manages a receive thread which adds responses to a 128 item ring
#buffer (LILO). Reads from the queue are synchronised through a Mutex so they may
#block briefly if the queue is in use. Writes to the target block.
#
#New protocol modules should take care to overload the mandatory functions (see
#the included modules for examples) and should take care of their own error handling
#because more or less none is done by Connector.
#
#When finished with a Connector object you should call Connector#close, otherwise the
#receive thread will hang around which can cause large memory leaks if you create many
#Connectors.
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class Connector

    QUEUE_MAXLEN=5000
    RETRIES=3

    #Stubs. Protocol module must override these methods.
    [:establish_connection, :blocking_read, :blocking_write, :is_connected?, :destroy_connection].each do |meth_name|
        define_method meth_name do
            raise RuntimeError, "Connector (fatal): protocol module did not implement the #{meth_name} method."
        end
        private meth_name
    end

    def initialize( proto_module, *module_args )
        @retries=RETRIES # proto modules might want this
        @module_args=module_args 
        self.extend proto_module # This must override the stub methods above.
        @queue=[]
        @queue_mutex=Mutex.new
        establish_connection
        # Start the receive thread
        Thread.abort_on_exception=true

        @recv_thread=Thread.new do
            while !(item=blocking_read).empty?
                @queue_mutex.synchronize { 
                    @queue << item #LILO
                    @queue.shift if @queue.length > QUEUE_MAXLEN # drop oldest item
                }
            end
        end

    end

    #Deliver a string to the peer using a blocking write.
    def deliver( data )
        blocking_write String(data)
    end

    #This will block until a response is received! Be prepared.
    def sr( item )
        begin
            deliver item
        rescue
            reconnect
            deliver item
        end
        sleep 0.05 while q_empty?
    end

    def quicksend( item )
        begin
            deliver item
        rescue
            reconnect
            deliver item
        end
    end


    #Are there items in the read queue?
    def queue_empty?
        @queue_mutex.synchronize {@queue.empty?}
    end
    alias q_empty? queue_empty?

    #Remove all items matching the supplied block from the queue
    #and return them as an array. Uses Array#select internally.
    #Uses a Mutex to access the queue
    #so it may block.
    def dequeue( &blk )
        @queue_mutex.synchronize {
            retarray = @queue.select &blk
            @queue -= retarray
            retarray
        }
    end
    alias dq dequeue

    #Remove the head item from the queue
    #and return it (Last In Last Out). Uses a Mutex to access the queue
    #so it may block.
    def dequeue_first
        @queue_mutex.synchronize {
            @queue.shift
        }
    end
    alias dq_first dequeue_first

    #Remove all items from the queue
    #and return them as an array. Uses a Mutex to access the queue
    #so it may block.
    def dequeue_all
        @queue_mutex.synchronize {
            @queue.slice!( (0..-1) )
        }
    end
    alias dq_all dequeue_all

    #Take a copy of the queue but leave the items in place.
    def queue_copy_all
        @queue_mutex.synchronize {
            @queue[0..-1]
        }
    end
    alias qc_all queue_copy_all

    #Close the connection to the remote host. For some protocols this just closes the
    #local socket, for connection-oriented protocols like TCP it will reset the connection
    #with the peer. All that is defined by the connection module in destroy_connection.
    def close
        # If the user doesn't call this they will leak memory, because the receive
        # thread will hang around... so yeah, call close. :)
        @recv_thread.kill rescue nil
        @queue_mutex=nil
        destroy_connection
    end

    #Returns a boolean.
    def connected?
        is_connected?
    end

    #Re-establish the connection. The initial connection is established as soon as the Connector is initialized,
    #so this should only be neccessary if the connection was closed or aborted.
    def reconnect
        destroy_connection if connected?
        establish_connection
    end

end
