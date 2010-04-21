require File.dirname(__FILE__) + '/grammar'
require File.dirname(__FILE__) + '/diff_engine'
require 'rubygems'
require 'trollop'
require 'distrib_diff_client'

OPTS = Trollop::options do 
    opt :grammar, "Filename of the saved grammar (from the C++ sequitur program)", :type => :string
    opt :old, "Filename of the old output", :type => :string
    opt :new, "Filename of the new output", :type => :string
    opt :old_modules, "YAML dump of the module list hash for the old file", :type => :string
    opt :new_modules, "YAML dump of the module list hash for the new file", :type => :string
end


mark=Time.now
engine=DiffBrokerClient.new("127.0.0.1",8888,OPTS[:grammar])
puts "Engine set up in #{Time.now - mark} seconds."
mark=Time.now
puts "Recompressing old sequence"
old_recompressed=engine.recompress(OPTS[:old])
puts "Recompression done in #{Time.now - mark} seconds. (#{old_recompressed.length})"
puts "Recompressing new sequence"
new_recompressed=engine.recompress(OPTS[:new])
puts "Recompression done in #{Time.now - mark} seconds.(#{new_recompressed.length})"
puts "Calling external sdiff"
# cheat here, by not writing out to tempfiles, OK for a test.
mark=Time.now
sdiff_output=`sdiff -d tracediff/recompressed-oldnodeschop.txt tracediff/recompressed-newnodesfull.txt`
puts "External sdiff done in #{Time.now - mark} seconds."
puts "Calling sdiff_markup in engine"
mark=Time.now
sd_markedup=engine.sdiff_markup( sdiff_output )
puts "Markup done in #{Time.now - mark} seconds."
sd_markedup[0].zip(sd_markedup[1]).each {|o,n|
    next unless o.chunk_type==:diff
    puts "#{o.offset}:#{o.size}(#{o.length})#{n.offset}:#{n.size}(#{n.length})"
}
