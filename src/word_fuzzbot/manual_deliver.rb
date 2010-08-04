require File.dirname(__FILE__) + '/wordops'
require 'rubygems'
require 'trollop'

OPTS = Trollop::options do 
    opt :log, "Print output to <filename>.log instead of stdout", :type => :boolean
    opt :norepairdialog, "Open with OpenNoRepairDialog", :type=> :boolean, :default=> false
    opt :debug, "Print debug info to stderr", :type => :boolean
end

if OPTS[:log]
    loghandle=File.open( "manualdeliver.log", "rb+" )
end

ARGV.each {|fname|

    w=Word.new
    p w
    warn "md Filename: #{fname}"
    w.set_visible
    status, details=w.deliver( fname, "", OPTS[:norepairdialog] )
    if OPTS[:log]
        loghandle.puts "FILENAME: #{fname} STATUS: #{status}"
        loghandle.puts details
    else
        puts "FILENAME: #{fname} STATUS: #{status}"
        puts details
    end
    w.destroy

}
loghandle.close
