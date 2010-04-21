input_files=ARGV

class Field
    attr_accessor :name, :length, :desc, :substruct_class, :comment
end

input_files.each {|filename|
    begin
        raw=File.read( filename )
    rescue
        $stderr.puts "Skipping file : #{$!}"
        next
    end
    structs=raw.scan(/struct.*?\}/m)
    class_length_index={}
    structs[0..-1].each {|s|
        this_struct_fields=[]
        classname=s.match(/struct (.*?) \{/)[1].capitalize rescue next
            puts "\nclass #{classname} < BinStruct"
            puts "# From file #{filename}"
            contents=s.match(/\{(.*)\}/m)[1]
            contents.split(';').map {|l| l.tr("\n\t",'')}.each {|l|
                comment=l.match(/\/\*(.*?)\*\//)[1..-1].join rescue false
                l.gsub!(/\/\*.*?\*\//,'') # remove comments
                l.sub!(/^ */,'') # compress spaces
                if l=~/:/
                    # There are multipe sub-byte length fields
                    l.split(',').each {|section|
                        ary=section.split(':').map {|e| e.scan(/\w+/)}
                        f=Field.new
                        f.name=ary[0].last
                        f.length=ary[1].first.to_i
                        this_struct_fields << f
                    }
                    (this_struct_fields.last.comment=comment) if comment
                next
                end
                # Otherwise it's just one field
                f=Field.new
                (f.comment=comment) if comment
                if l.match(/^struct/)
                    f.substruct_class=l.split(' ')[1].capitalize
                    substruct_name=l.split(' ')[2]
                    if count=(substruct_name.match(/\[(\d+)\]/)[1].to_i) rescue false
                        if count==0
                            f.length='buf.length'
                        else
                            for i in (0..count-1) do
                                f=Field.new
                                f.substruct_class=l.split(' ')[1].capitalize
                                f.name=substruct_name.match(/(\w+)\[\d+\]/)[1]
                                f.name="#{f.name}#{i}"
                                f.length="#{f.substruct_class}.length"
                                this_struct_fields << f
                            end
                            next
                        end
                        f.name=substruct_name.match(/(\w+)\[\d+\]/)[1]
                    else
                        f.name=substruct_name
                        f.length="#{f.substruct_class}.length"
                    end
                    this_struct_fields << f
                    next
                end
                split_line=l.split(' ')
                next if split_line.empty?
                case split_line[0]
                when /u_int/
                    f.length=split_line[0].match(/u_int(\d+)/)[1].to_i
                    name=split_line[1]
                when "int"
                    f.length=32 
                    name=split_line[1]
                when "unsigned"
                    f.length=32 
                    name=split_line[2]
                when "char"
                    f.length=8
                    name=split_line[1]
                when "long"
                    if split_line[1]=="long" # long long
                        f.length=64
                        name=split_line[4]
                    else
                        f.length=32
                        name=split_line[3]
                    end
                when "enum"
                    f.length=32
                    name=split_line[1]
                else
                    f.length="FIXME!!"
                    name=split_line[0..1].join('_')
                end
                if name=~/\[\d+\]/
                    # repeated elements, or rest of packet
                    f.name=l.match(/(\w+)\[\d+\]/)[1]
                    if l=~/\[0\]/
                        f.length='buf.length'
                    else
                        f.length*=l.match(/\[(\d+)\]/)[1].to_i
                    end
                else
                    f.name=name
                end
                this_struct_fields << f
            }
            # fields should all be built now
            if this_struct_fields.all? {|f| f.length.is_a? Integer}
                class_length_index[classname]=this_struct_fields.inject(0) {|s,field| s+=field.length}
                puts "# Fixed length: #{class_length_index[classname]} bits"
            end
            puts "parse {|buf|"
            this_struct_fields.each {|field|
                puts "    # #{field.comment}" if field.comment
                if field.substruct_class
                    if class_length_index[field.substruct_class]
                        puts "    substruct buf, :#{field.name}, #{class_length_index[field.substruct_class]}, #{field.substruct_class}" 
                        field.length=class_length_index[field.substruct_class]
                    else
                        puts "    substruct buf, :#{field.name}, #{field.length}, #{field.substruct_class}" 
                    end
                else
                    puts "    unsigned buf, :#{field.name}, #{field.length}, \"Parsed as #{field.name}\""
                end
            }
            puts "}"
            puts "end\n"
        }
    }
