require File.dirname(__FILE__) + '/word_delivery_agent'
require 'rubygems'
require 'trollop'

OPTS = Trollop::options do 
    opt :log, "Print output to ./manualdeliver.log instead of stdout", :type => :boolean
    opt :norepair, "Open with without repair (not default for Word)", :type=> :boolean
    opt :clean, "Open a new process for each test", :type=> :boolean
    opt :debug, "Print debug info to stderr", :type => :boolean
end

output=( OPTS[:log] ? File.open( "manualdeliver.log", "wb+" ) : $stdout )

delivery_options=[]
delivery_options << "clean" if OPTS [:clean]
delivery_options << "norepair" if OPTS [:norepair]

w=WordDeliveryAgent.new( :visible=>true )

ARGV.shuffle.each {|fname|
    status, details=w.deliver( fname, delivery_options )
    output.puts "FILENAME: #{fname} STATUS: #{status}"
    output.puts details if status=="crash"
}
