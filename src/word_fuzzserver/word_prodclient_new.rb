require File.dirname(__FILE__) + '/../core/production_client_new'
require 'trollop'

OPTS = Trollop::options do 
    opt :producer, "File with .rb code implementing a Producer generator", :type => :string, :required=>true
    opt :debug, "Turn on debug mode", :type => :boolean
    opt :clean, "Run clean (new process for each test)", :type=>:boolean
    opt :norepair, "Tell Word not to automatically repair", :type=>:boolean
    opt :servers, "Filename containing servers (name or ip) to connect to, one per line", :type => :string
    stop_on 'opts'
end

ARGV.shift # to clear the 'opts' string

# The most basic possible implementation of a production client. The parameter
# is the filename of a test case generator which defines the Producer class.
# See the example producers - the Producer generator will get instantiated and
# all of its tests sent.
#
# You can, of course, run this script multiple times with a different Producer
# each time, to make full use of multi-core machines. The FuzzServer will farm
# the tests out (unintelligently) to the clients.
#
# The command line is basically global opts like -p producer.rb -s serverlist.txt
# followed by 'opts' and then options for the production generator itself
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
    'poll_interval'=>60,
    'queue_name'=>'word'
)
ProductionClient.production_generator=Producer.new( ARGV, ProductionClient )
ProductionClient.fuzzbot_options << "clean" if OPTS[:clean]
ProductionClient.fuzzbot_options << "norepair" if OPTS[:norepair]

EM.epoll
EM.set_max_timers(5000000)
EventMachine::run {

    @producer=File.basename(OPTS[:producer])
    @args=ARGV.join(' ')

    EM.add_periodic_timer(20) do 
        @old_time||=Time.now
        @old_total||=ProductionClient.case_id
        @total=ProductionClient.case_id
        @results=ProductionClient.lookup[:results].to_a.map {|a| a.join(': ')}.join(', ')
        @classifications=ProductionClient.lookup[:classifications].to_a.map {|a| a.join(': ')}.join(', ')
        puts "#{@producer} + #{@args} => #{@total} @ #{"%.2f" % ((@total-@old_total)/(Time.now-@old_time).to_f)} #{@results} (#{ProductionClient.lookup[:buckets].keys.size}) #{@classifications}"
        until ProductionClient.queue[:bugs].empty?
            puts "#{@producer} + #{@args} BOOF! #{ProductionClient.queue[:bugs].shift}"
            p ProductionClient.lookup[:buckets]
        end
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
