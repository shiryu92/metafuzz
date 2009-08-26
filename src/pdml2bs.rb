require 'libxml'

infile=ARGV[0]
outfile=ARGV[1]
protofilter=ARGV[2..-1]
begin
  doc=XML::Document.file(infile)
  out=File.new(outfile, 'w+')
rescue
  puts $!
  puts "Usage: #{$0} pdml_file output_file [proto proto ... proto]"
  puts "only packets containing protocols listed on the command line will be included."
  exit
end

root=doc.root
root.find('packet').to_a.each do |packet|
  begin
    framenum=packet.find('proto/field').to_a.select {|f| f['name']=='frame.number'}.first['show']
    protos=packet.find('proto').to_a
    unless protofilter.empty?
      next unless protos.any? {|proto| protofilter.any? {|filter| filter==proto['name']}}
    end
    # Only write definitions for the layers below TCP / UDP, or
    # below IP if there are no TCP / UDP headers.
    hasip=protos.find {|proto| proto['name']=='ip'}
    ipindex=(hasip ? protos.index(hasip) : nil)
    haslower=protos.find {|proto| proto['name']=='tcp' || proto['name']=='udp'}
    lowerindex=(haslower ? protos.index(haslower) : nil)
    unless hasip or haslower
      out.puts "# Skipping frame #{framenum}, no IP content."
      next
    end
    parsed=[]

    # Parse the XML to pull the packet fields
    packet.find('proto').to_a[(lowerindex || ipindex)+1..-1].each do |proto| 
      values=[]
      proto.find('field').each do |f| 
        name=f['showname']? f['showname'] : f['show']
        type='hexstring'
        type='unsigned' if name && name.split(/[:(]/)[1].strip=~/^[0-9]*$/ and f['size'].to_i <=4 rescue false
        type='unsigned' if f['size'].to_i <= 2
        shortname=name.split(/[:(]/)[0].downcase.strip.split(' ').join('_')
        size=f['size'].to_i*8
        value=( type=='hexstring'? "\"#{f['value']}\"" : f['value'].hex )
        values << [shortname, type, size, value]
      end
      parsed << [proto['name'], values]
    end

    # Make sure there are no duplicate field names
    seen = Hash.new{|h,k|h[k]=-1};
    parsed.map {|protname, arr|
      arr.map {|name, type, size, val|
        count=seen[name]+=1
        name << (count>0? count.to_s : '')
      }
    }

    out.puts "class Packet#{framenum} < Binstruct"
    # Write field definitions
    parsed.each {|protname, arr|
      out.puts "\t##{protname}"
      arr.each {|name, type, size, val|
        out.printf "\t%s\t:%-16s\t%d\n", type, name, size
      }
    }
    out.puts
    # Write default values
    parsed.each {|protname, arr|
      arr.each {|name, type, size, val|
        out.printf "\tdefault_value\t:%-16s\t%s\n", name+',', val
      }
    }
    out.puts "end"
  rescue
    out.puts "# Unable to parse packet #{framenum||=''}."
    out.puts "# #{$!}"
  end
  out.puts
end
out.close
