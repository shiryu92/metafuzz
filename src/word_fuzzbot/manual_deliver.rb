require File.dirname(__FILE__) + '/wordops'
require 'rubygems'
require 'trollop'

OPTS = Trollop::options do 
    opt :log, "Print output to <filename>.log instead of stdout", :type => :boolean
    opt :norepair, "Open with without repair (not default for Word)", :type=> :boolean
    opt :reuse, "Reuse process", :type=> :boolean
    opt :debug, "Print debug info to stderr", :type => :boolean
end

if OPTS[:log]
    loghandle=File.open( "manualdeliver.log", "wb+" )
end

w=Word.new if OPTS[:reuse]

ARGV.shuffle.each {|fname|

    begin
        w=Word.new unless OPTS[:reuse]
        w.set_visible
        # default for norepair is false, which means repair, which is the
        # Word default
        status, details=w.deliver( fname, "", (not OPTS[:norepair]) )
        if OPTS[:log]
            loghandle.puts "FILENAME: #{fname} STATUS: #{status}"
            loghandle.puts details if status=="crash"
        else
            puts "FILENAME: #{fname} STATUS: #{status}"
            puts details if status=="crash"
        end
        w.destroy unless OPTS[:reuse]
        w.close_documents if OPTS[:reuse]
    rescue
        w=Word.new unless w.is_connected?
    end

}
loghandle.close
