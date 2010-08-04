require File.dirname(__FILE__) + '/wordops'
require 'rubygems'
require 'trollop'

OPTS = Trollop::options do 
    opt :log, "Print output to <filename>.log instead of stdout", :type => :boolean
    opt :debug, "Print debug info to stderr", :type => :boolean
end

ARGV.each {|fname|

    w=Word.new
    w.set_visible
    status, details=w.deliver fname
    if OPTS[:log]
        File.open( fname, "rb+" ) {|io| io.write details}
    else
        puts details
    end
    w.destroy

}
