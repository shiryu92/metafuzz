require File.dirname(__FILE__) + '/pin_dump_structures'
require 'rubygems'
require 'trollop'

OPTS = Trollop::options do 
    opt :arch, "Architecture (32 or 64)", :type => :integer, :default=>32
end

Trollop::die unless (OPTS[:arch]==32 || OPTS[:arch]==64)

ARGV.each {|fname|

    stream=File.open( fname, "rb+") {|io| io.read}
    while stream.size > 0
        this_record=TraceRecord.new( stream, OPTS[:arch] )
        p this_record
        sleep 3
    end

}

