# Some test code to mark up modules in diffed, sequitur compressed
# output.
# (c) Ben Nagy, 2010

require File.dirname(__FILE__) + '/tracepp_lib.rb'
require 'rubygems'
require 'trollop'

OPTS = Trollop::options do 
    opt :template, "Use the given template filename", :type => :string
    opt :old, "Base filename (can be the template filename)", :type => :string
    opt :debug, "Print debug info to stderr", :type => :boolean
end

ARGV.each {|fname|

    stem=File.join(File.dirname(fname),File.basename(fname, ".txt"))
    template_stem=File.join(File.dirname(OPTS[:template]),File.basename(OPTS[:template], ".txt"))
    old_stem=File.join(File.dirname(OPTS[:old]),File.basename(OPTS[:old], ".txt"))

    diff_engine=TracePP::TracePPDiffer.new( OPTS[:template], OPTS[:old], fname )
    sdiff||=File.read( old_stem + "-" + File.basename(stem) + TracePP::SDIFF )
    old, new=diff_engine.sdiff_markup( sdiff )
    old.zip(new).each_with_index {|pair, idx| 
        o,n=pair
        puts "<#{idx}>#{o.chunk_type} at #{o.offset}:#{o.size}(#{o.length}) / #{n.offset}:#{n.size}(#{n.length})"
        if o.chunk_type==:diff
            old_offset=o.offset
            new_offset=n.offset
            o.zip(n).each {|pair|
                line=[
                    old_offset,
                    diff_engine.prettify_token_old(pair[0]),
                    new_offset,
                    diff_engine.prettify_token_new(pair[1])
                ]
                puts "(%d)%-38s    (%d)%-38s" % line
                old_offset+=diff_engine.token_size( pair[0] )
                new_offset+=diff_engine.token_size( pair[1] )
            }
            unless old_offset==o.size && new_offset==n.size
                warn "Something wrong with offsets"
                sleep 1
            end
        end
    }
}
