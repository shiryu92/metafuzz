require File.dirname(__FILE__) + '/wordops'
require 'rubygems'
require 'trollop'

OPTS = Trollop::options do 
    opt :log, "Print output to <filename>.log instead of stdout", :type => :boolean
    opt :norepairdialog, "Open with OpenNoRepairDialog", :type=> :boolean
    opt :reuse, "Reuse process", :type=> :boolean
    opt :debug, "Print debug info to stderr", :type => :boolean
end

if OPTS[:log]
    loghandle=File.open( "manualdeliver.log", "rb+" )
end

w=Word.new if OPTS[:reuse]

ARGV.shuffle.each {|fname|

    w=Word.new unless OPTS[:reuse]
    warn "md Filename: #{fname}"
    w.set_visible
    status, details=w.deliver( fname, "", OPTS[:norepairdialog] )
    if OPTS[:log]
        loghandle.puts "FILENAME: #{fname} STATUS: #{status}"
        loghandle.puts details if status=="crash"
    else
        puts "FILENAME: #{fname} STATUS: #{status}"
        puts details if status=="crash"
    end
    w.destroy unless OPTS[:reuse]
    w.close_documents if OPTS[:reuse]

}
loghandle.close
