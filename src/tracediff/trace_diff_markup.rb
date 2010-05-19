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
            seq_offsets={:old=>o.offset, :new=>n.offset}
            o.zip(n).each {|old_tok, new_tok|
                line=([[old_tok,:old],[new_tok,:new]].map {|token, which_db|
                    if token[0]=='&'
                        # It's a single tuple
                        hit_count=diff_engine.hit_count(which_db, seq_offsets[which_db] )
                        pretty=diff_engine.prettify_token( which_db, token )
                        "#{hit_count}:#{pretty}"
                    else
                        # It's a rule
                        pretty=diff_engine.prettify_token( which_db, token )
                        "#{pretty}"
                    end
                })
                puts( "%-38s    %-38s" % line )
                seq_offsets[:old]+=diff_engine.token_size( old_tok )
                seq_offsets[:new]+=diff_engine.token_size( new_tok )
            }
            unless old_offset==(o.offset+o.size) && new_offset==(n.offset+n.size)
                warn "Something wrong with seq_offsets"
                sleep 1
            end
        end
    }
}
