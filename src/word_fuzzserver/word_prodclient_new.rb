require File.dirname(__FILE__) + '/../core/production_client_new'
require ARGV[0]

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

ProductionClient.setup( 
    'debug'=>false,
    'production_generator'=>Producer.new,
    'queue_name'=>'word',
    'template'=>Producer.const_get( :Template ),
    'template_hash'=>Digest::MD5.hexdigest( Producer.const_get(:Template) )
)

EM.epoll
EM.set_max_timers(5000000)
EventMachine::run {
    EventMachine::connect(ProductionClient.server_ip,ProductionClient.server_port, ProductionClient)
}
puts "Event loop stopped. Shutting down."
