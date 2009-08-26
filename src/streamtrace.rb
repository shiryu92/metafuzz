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

# WARNING!!! This may not work for anything except IP/TCP/UDP etc
# when parsing wireshark dumps because the sub-protocols are not
# consistent in the way they use the <field name=...> attribute.
def blat(node, hsh={}, root=true)
  # if this is the root node, attach the children to it directly
  if root
    node.each {|child|
      blat( child, hsh, false )
    }
    return hsh
  end
  # else if this node has children, create a substruct and recurse
  if node.child?
    sub={}
    hsh["#{node['name'].split('.').last rescue "???"}"]=sub
    node.each {|child|
      blat( child, sub, false )
    }
    if node['show']
      sub["value"]=node['show']
    end
  else
    # otherwise, attach the value to this struct
    hsh["#{node['name'].split('.').last}"]=node['show'] if node['name']
  end
end

interesting=[]
root.find('packet').each {|pkt|
  pack=blat(pkt)
  interesting << pack if pack['frame']['protocols'].split(':').any? {|prot| prot=='pptp' or prot=='gre'}
}
speakers=interesting.map {|pkt| pkt['ip']['src']}.uniq
puts "#{speakers.length} speakers."
speakers.each {|speaker|
  puts "#{speaker}: #{interesting.select {|pkt| pkt['ip']['src']==speaker}.length} packets."
}
puts "#{interesting.first['ip']['src']} speaks first."
from_src, from_dest=interesting.partition {|pkt| pkt['ip']['src']==interesting.first['ip']['src']}
puts interesting.min {|a,b| a['frame']['time_delta'].to_f <=> b['frame']['time_delta'].to_f}['frame']['time_delta']
puts interesting.max {|a,b| a['frame']['time_delta'].to_f <=> b['frame']['time_delta'].to_f}['frame']['time_delta']
puts interesting.map {|pkt| pkt['frame']['time_delta'].to_f}.sort.first(interesting.length - (interesting.length*0.1).round).last
puts interesting.map {|pkt| pkt['frame']['time_delta'].to_f}.sort.reverse.first(interesting.length - (interesting.length*0.1).round).last


