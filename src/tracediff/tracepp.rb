require 'rubygems'
require 'json'
require 'oklahoma_mixer'
require File.dirname(__FILE__) + '/tracepp_lib'
include TracePP
require File.dirname(__FILE__) + '/grammar'
require File.dirname(__FILE__) + '/recompressor'
require 'trollop'

# TI - Tuple Index - a tuple is a from->to pair of memory addresses, which are two-way indexed in a Hash DB
# The TI will will created by the template and used for all variants
# TIS - Tuple Index Sequence - the runtrace sequence of tuple indicies, without state, for sequitur compression
# RTIS - Recompressed TIS
# ROTIS - Recompressed Original TIS
# RVTIS - Recompressed Variant TIS
# Trie - The data structure which is used for Recompression

OPTS = Trollop::options do 
    opt :sequitur_path, "Full path to sequitur binary", :type => :string, :required => true
    opt :create_template, "Process as a new template (produces grammar)", :type => :boolean
    opt :template, "Use the given template filename", :type => :string
    opt :old, "Base filename (can be the template filename)", :type => :string
    opt :debug, "Print debug info to stderr", :type => :boolean
    opt :existing, "Use existing .pp files, if they exist", :type => :boolean
end

TL_PACK_STRING=TracePP::TraceLine.pack_string
    
def populate_dbs( fname )
    begin
        stem=File.join(File.dirname(fname),File.basename(fname, ".txt"))
        if (File.exists?( stem + TI ))  &&
           (File.exists?( stem + TIS )) &&
           (File.exists?( stem + MOD )) &&
           (File.exists?( stem + RAW)) &&
           OPTS[:existing] then return end
        fh=File.open(fname, "rb")
        if OPTS[:create_template]
            tuple_index_db=OklahomaMixer.open(stem + TI, :mode=>'wct', :rcnum=>1000000)
        else
            template_stem=File.join(File.dirname(OPTS[:template]),File.basename(OPTS[:template], ".txt"))
            tuple_index_db=OklahomaMixer.open(template_stem + TI, :mode=>'w', :rcnum=>1000000)
        end
        module_db=OklahomaMixer.open(stem + MOD, :mode=>'wct', :rcnum=>1000000)
        trace_line_db=OklahomaMixer.open(
            stem + RAW,
            :width=>49,
            :limsiz=>2*1024*1024*1024,
            :rcnum=>1000000,
            :mode=>'wct'
        ) # 2GB size limit, overwrite any existing dbs, 49 byte record size 
        tis_handle=File.open(stem + TIS,"wb+")
        tuple_counter=Hash.new( 0 )
        unpacked=[]
        until fh.eof?
            raw_line=fh.readline
            this_line=JSON.parse(raw_line)
            if this_line["type"]=="module"
                module_db[this_line["name"]]="#{this_line["base"]} #{this_line["base"]+this_line["size"]} #{this_line["checksum"]}"
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
        if OPTS[:create_template]
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
    tis_stem=File.join(File.dirname(tis_fname),File.basename(tis_fname, TIS))
    unless OPTS[:create_template]
        template_stem=File.join(File.dirname(OPTS[:template]),File.basename(OPTS[:template], ".txt"))
    end
    begin
        if OPTS[:create_template]
            # Create new sequitur grammar and trie
            `#{OPTS[:sequitur_path]} -d -p -q < #{tis_fname} > #{tis_stem + GRAMMAR}`
            gram=Grammar.new(tis_stem + GRAMMAR)
            trie=Recompressor::Trie.new(tis_stem + TRIE)
            mark=Time.now if OPTS[:debug]
            recompressor=Recompressor.new( gram, trie, build=true )
            warn "Built Trie: #{Time.now - mark}" if OPTS[:debug]
        else
            # open existing grammar and trie
            gram=Grammar.new(template_stem + GRAMMAR)
            # existing file, will be opened RO
            trie=Recompressor::Trie.new(template_stem + TRIE) 
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

def postprocess
    if OPTS[:create_template]
        files=ARGV
    else
        files=[OPTS[:old], *ARGV]
    end
    files.each {|fname|
        warn "Processing #{fname}" if OPTS[:debug]
        stem=File.join(File.dirname(fname),File.basename(fname, ".txt"))
        unless OPTS[:create_template]
            template_stem=File.join(File.dirname(OPTS[:template]),File.basename(OPTS[:template], ".txt"))
            old_stem=File.join(File.dirname(OPTS[:old]),File.basename(OPTS[:old], ".txt"))
        end
        begin
            #
            # Step 1. Populate the tis.txt, tis.tch, mod.tch and .raw.tcf
            #
            mark=Time.now if OPTS[:debug]
            populate_dbs( fname )
            warn "Populate DBs: #{Time.now - mark}" if OPTS[:debug]
            #
            # Step 2. Recompress the TIS based on the template's sequitur grammar
            # For templates, create the grammar.txt and trie.tch
            #
            mark=Time.now if OPTS[:debug]
            # recompress_tis always uses the template grammar
            File.open(stem + RTIS, "wb+") {|io|
                io.puts( recompress_tis( stem + TIS ) ) 
            } unless (OPTS[:existing]) && (File.exists?( stem + RTIS ))
            warn "Recompress TIS: #{Time.now - mark}" if OPTS[:debug]
            return if OPTS[:create_template] # nothing else to do for a template
            next if fname == OPTS[:old] # The old file is processed first, can't diff yet.
            #
            # Step 3. Get the sdiff of the ROTIS and the RVTIS
            #
            mark=Time.now if OPTS[:debug]
            unless OPTS[:existing] && (File.exists?( old_stem + "-" + File.basename(stem) + SDIFF )) 
                sdiff=`sdiff -d #{old_stem + RTIS} #{stem + RTIS}`
                File.open(old_stem + '-' + File.basename(stem) + SDIFF, "wb+") {|io|
                    io.puts( sdiff ) 
                }
            end
            warn "OS sdiff: #{Time.now - mark}" if OPTS[:debug]
            #
            # Step 4. Convert the sdiff to chunks
            #
            mark=Time.now if OPTS[:debug]
            diff_engine=TracePP::TracePPDiffer.new( OPTS[:template], OPTS[:old], fname )
            sdiff||=File.read( old_stem + "-" + File.basename(stem) + SDIFF )
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

postprocess
