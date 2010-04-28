require 'rubygems'
require 'json'
require 'oklahoma_mixer'
require File.dirname(__FILE__) + '/tracepp_lib'
require File.dirname(__FILE__) + '/grammar'
require File.dirname(__FILE__) + '/diff_engine'
require File.dirname(__FILE__) + '/recompressor'
require 'trollop'

# TI - Tuple Index - a tuple is a from->to pair of memory addresses, which are two-way indexed in a Hash DB
# The TI will will created by the template and used for all variants
# TIS - Tuple Index Sequence - the runtrace sequence of tuple indicies, without state, for sequitur compression
# RTIS - Recompressed TIS
# ROTIS - Recompressed Original TIS
# RVTIS - Recompressed Variant TIS

OPTS = Trollop::options do 
    opt :sequitur_path, "Full path to sequitur binary", :type => :string, :required => true
    opt :new_template, "Process as a new template (produces grammar)", :type => :boolean
    opt :template, "Process as a variant from the given template filename", :type => :string
    opt :debug, "Print debug info to stderr", :type => :boolean
    opt :existing, "Use existing .pp files, if they exist", :type => :boolean
end

TL_PACK_STRING=TracePP::TraceLine.pack_string
    
def populate_dbs( fname )
    begin
        fh=File.open(fname, "rb")
        stem=File.join(File.dirname(fname),File.basename(fname, ".txt"))
        if OPTS[:new_template]
            tuple_index_db=OklahomaMixer.open(stem +".pp.ti.tch", :mode=>'wct')
        else
            template_stem=File.join(File.dirname(OPTS[:template]),File.basename(OPTS[:template], ".txt"))
            tuple_index_db=OklahomaMixer.open(template_stem +".pp.ti.tch", :mode=>'w')
        end
        module_db=OklahomaMixer.open(stem +".pp.mod.tch", :mode=>'wct')
        trace_line_db=OklahomaMixer.open(
            stem +".pp.raw.tcf",
            :width=>49,
            :limsiz=>2*1024*1024*1024,
            :mode=>'wct'
        ) # 2GB size limit, overwrite any existing dbs, 49 byte record size 
        tis_handle=File.open(stem + ".pp.tis.txt","wb+")
        tuple_counter=Hash.new( 0 )
        unpacked=[]
        until fh.eof?
            raw_line=fh.readline
            this_line=JSON.parse(raw_line)
            if this_line["type"]=="module"
                module_db["module:#{this_line["name"]}:start"]=this_line["base"]
                module_db["module:#{this_line["name"]}:end"]=this_line["base"]+this_line["size"]
                module_db["module:#{this_line["name"]}:checksum"]=this_line["checksum"]
            else
                this_tuple="#{this_line["from"]}->#{this_line["to"]}"
                tuple_counter[this_tuple]+=1
                unless key=tuple_index_db[this_tuple]
                    # Not seen before, add new two-way entry to the Hash DB
                    key=tuple_index_db.store("globals:tuple_index", 1, :add)
                    tuple_index_db[key]=this_tuple
                    tuple_index_db[this_tuple]=key
                end
                # The TIS is for input into the recompression program
                tis_handle.puts "#{key}"
                # Write the full trace line to the fixed length db
                unpacked.clear
                unpacked << TracePP::TraceLine.type_to_int( this_line["type"] )
                unpacked << this_line["from"]
                unpacked << this_line["to"]
                unpacked << this_line["state"]["eax"]
                unpacked << this_line["state"]["ebx"]
                unpacked << this_line["state"]["ecx"]
                unpacked << this_line["state"]["edx"]
                unpacked << this_line["state"]["esp"]
                unpacked << this_line["state"]["ebp"]
                unpacked << this_line["state"]["esi"]
                unpacked << this_line["state"]["edi"]
                unpacked << this_line["state"]["flags"]
                unpacked << tuple_counter[this_tuple]
                packed=unpacked.pack( TL_PACK_STRING ) 
                trace_line_db.store(:next, packed)
            end
        end
        if OPTS[:new_template]
            tuple_index_db["globals:max_orig_id"]=tuple_index_db["globals:tuple_index"]
        else
            tuple_index_db["globals:maxid:#{fname}"]=tuple_index_db["globals:tuple_index"]
        end
    ensure
        tuple_index_db.close rescue nil
        trace_line_db.close rescue nil
        tis_handle.close rescue nil
        module_db.close rescue nil
        fh.close rescue nil
    end
end

def recompress_tis( tis_fname )
    tis_stem=File.join(File.dirname(tis_fname),File.basename(tis_fname, ".pp.tis.txt"))
    unless OPTS[:new_template]
        template_stem=File.join(File.dirname(OPTS[:template]),File.basename(OPTS[:template], ".txt"))
    end
    begin
        if OPTS[:new_template]
            # Create new sequitur grammar and trie
            `#{OPTS[:sequitur_path]} -d -p -q < #{tis_fname} > #{tis_stem + ".pp.grammar.txt"}`
            gram=Grammar.new(tis_stem + ".pp.grammar.txt")
            trie=Recompressor::Trie.new(tis_stem + ".pp.trie.tch")
            recompressor=Recompressor.new( gram, trie, build=true )
        else
            # open existing grammar and trie
            gram=Grammar.new(template_stem + ".pp.grammar.txt")
            trie=Recompressor::Trie.new(template_stem + ".pp.trie.tch")
            recompressor=Recompressor.new( gram, trie, build=false )
        end
        # The sequitur grammar prepends '&' to raw symbols and uses ints
        # for rule numbers, so we need to feed the TIS with '&'s
        stream=Recompressor::Stream.new( tis_fname ) {|fh| "&#{fh.readline.chomp}"}
            # Do the recompression!
            recompressor.recompress( stream )
    ensure
        trie.close rescue nil
        stream.close rescue nil
    end
end

def postprocess( fname_ary )
    fname_ary.each {|fname|
        stem=File.join(File.dirname(fname),File.basename(fname, ".txt"))
        unless OPTS[:new_template]
            template_stem=File.join(File.dirname(OPTS[:template]),File.basename(OPTS[:template], ".txt"))
        end
        begin
            #
            # Step 1. Populate the tis.txt, tis.tch, mod.tch and .raw.tcf
            #
            mark=Time.now if OPTS[:debug]
            populate_dbs( fname )
            warn "Populate DB: #{Time.now - mark}" if OPTS[:debug]
            #
            # Step 2. Recompress the TIS based on the template's sequitur grammar
            # For templates, create the grammar.txt and trie.tch
            #
            mark=Time.now if OPTS[:debug]
            File.open(stem + ".pp.rtis.txt", "wb+") {|io|
                io.puts( recompress_tis( stem + ".pp.tis.txt" ) ) 
            }
            warn "Recompress TIS: #{Time.now - mark}" if OPTS[:debug]
            return unless OPTS[:template] # nothing else to do for a template
            #
            # Step 3. Get the sdiff of the ROTIS and the RVTIS
            #
            mark=Time.now if OPTS[:debug]
            sdiff=`sdiff -d #{template_stem+".pp.rtis.txt"} #{stem + ".pp.rtis.txt"}`
            warn "OS sdiff: #{Time.now - mark}" if OPTS[:debug]
            #
            # Step 4. Convert the sdiff to chunks
            #
            mark=Time.now if OPTS[:debug]
            gram=Grammar.new(template_stem + ".pp.grammar.txt")
            diff_engine=TracePP::TracePPDiffer.new( gram )
            chunks=diff_engine.sdiff_markup( sdiff )
            warn "Markup and create chunks: #{Time.now - mark}" if OPTS[:debug]
            #
            # Step 5. Store the chunks in a DB
            #
        rescue Exception => e
            warn "Error with #{fname}: #{$!}"
            warn e.backtrace
            next
        end
    }
end

# Do option validation here

postprocess( ARGV )
