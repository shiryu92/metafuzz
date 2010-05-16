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
    old.zip(new).each {|o, n| 
        puts "#{o.chunk_type} at #{o.offset}:#{o.size}(#{o.length}) / #{n.offset}:#{n.size}(#{n.length})"
        if o.length!=n.length
            puts "wtf?"
            p o
            p n
            puts "/wtf"
        end
        if o.chunk_type==:diff
            o.zip(n).each {|pair|
                p pair
                sleep 1
                puts "%-20.20s     %-20.20s" % [diff_engine.prettify_token_old(pair[0]),diff_engine.prettify_token_new(pair[1])]
            }
            next
            puts "EXPANDING"
            old_expanded=o.map {|elem| diff_engine.expand_rule( elem,2 )}.flatten
            new_expanded=n.map {|elem| diff_engine.expand_rule( elem,2 )}.flatten
            old_diffed,new_diffed=StreamDiff.diff_and_markup(old_expanded, new_expanded)
            old_diffed.zip( new_diffed ).each {|od,nd|
                puts "#{od.chunk_type}:#{od.size} -- #{nd.chunk_type}:#{nd.size}"
                next unless od.chunk_type==:diff
                od.zip(nd).each {|a,b| puts "%-20.20s   %-20.20s" % [diff_engine.prettify_token_old(a),diff_engine.prettify_token_new(b)]}
            }
        end
    }
}
