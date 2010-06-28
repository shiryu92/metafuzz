require File.dirname(__FILE__) + '/../core/production_client_new'
require 'trollop'

OPTS = Trollop::options do 
    opt :producer, "File with .rb code implementing a Producer generator", :type => :string, :required=>true
    opt :template, "Template filename", :type=>:string
    opt :debug, "Turn on debug mode", :type => :boolean
    opt :servers, "Filename containing servers (name or ip) to connect to, one per line", :type => :string
end

# The most basic possible implementation of a production client. The parameter
# is the filename of a test case generator which defines the Producer class.
# See the example producers - the Producer generator will get instantiated and
# all of its tests sent.
#
# You can, of course, run this script multiple times with a different Producer
# each time, to make full use of multi-core machines. The FuzzServer will farm
# the tests out (unintelligently) to the clients.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

require OPTS[:producer]

ProductionClient.setup( 
    'debug'=>OPTS[:debug],
    'poll_interval'=>30,
    'production_generator'=>Producer.new( OPTS[:template] ),
    'queue_name'=>'word',
    'template'=>File.read( OPTS[:template] ),
    'template_hash'=>Digest::MD5.hexdigest( File.read(OPTS[:template]) )
)

EM.epoll
EM.set_max_timers(5000000)
EventMachine::run {

    EM.add_periodic_timer(20) do 
        @old_time||=Time.now
        @old_total||=ProductionClient.case_id
        @total=ProductionClient.case_id
        print "\rTotal: #{@total}, Speed: #{"%.2f" % ((@total-@old_total)/(Time.now-@old_time).to_f)}    "
        @old_total=@total
        @old_time=Time.now
    end

    if OPTS[:servers]
        File.read( OPTS[:servers] ).each_line {|l|
                EventMachine::connect( l.chomp, ProductionClient.server_port, ProductionClient )
        }
    else
        EventMachine::connect(ProductionClient.server_ip,ProductionClient.server_port, ProductionClient)
    end
}
puts "Event loop stopped. Shutting down."
