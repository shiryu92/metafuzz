require 'fields'
require 'objhax'

#The Binstruct constructor class is mainly designed for building structures, but at a pinch it can be used
#as a half-decent parser for both packed binary and tokenised strings.
#New Binstruct objects are created with an abbreviated syntax. The basic field construction is:
# fieldtype symbol, length, description, condition (optional)
#The <tt>length</tt> parameter can be a number, expression or a string containing ruby code that will
#be evaluated in the namespace of the object being initialized when parsing data. This means that code strings have access
#to the variables <tt>buffer</tt> for the raw input and <tt>bitstring</tt> for the binary string conversion
#of the buffer. This allows lengths to be calculated based on fields that have already been set up, the entire <tt>buffer</tt>
#, (which is never altered) or the remaining
#contents of the <tt>bitstring</tt> (which is <tt>slice!</tt> ed each time a field is created). One example would be seeking
#forward to the next null character or other terminator.
#
#The optional condition paramter is another code string which is evaluated in the namespace of the object being created. If the condition evaluates
#to <tt>false</tt> then the field will be skipped. This is useful in some protocols which create different fields as a result of an earlier type field or
#flag.
#
#Other commands can be used once the fields are defined. 
#At the moment, <tt>default_value</tt>, <tt>randomize</tt> and <tt>separator</tt> are the
#only supported extra commands.
#
#Here is an example structure which is used in the Binstruct specification file:
# class DataAttrib < Binstruct
#   unsigned :flag, 1, "Attribute Format Flag"
#   signed :type, 15, "Attribute Type"
#   unsigned :length, 16, "Attribute Length", "self.flag==0"
#   bitstring :flags, 13, "Some Flags"
#   bitstring :pad, 3, "Random Padding"
#   hexstring :testhex, 64, "Some hex data"
#   string :teststr, 32, "Some string data"
#   octetstring :ipaddr, 32, "IP Address"
#   string :long_value, "self.length", "Attribute Value", "self.flag==0"
#   unsigned :short_value, 8*2, "Attribute Value", "self.flag==1"
#   default_value :type, -23
#   default_value :long_value, "faff"
#   default_value :flag, 1
#   default_value :short_value, 13
#   default_value :ipaddr, "192.168.13.12"
# end
#
#And here is an example structure which uses the string tokenizer instead of the bitlength parser.
#Note that you can use any value you like for length if you define a separator, it parses by tokenizing
#the string (currently using str.split(separator)).
# class HTTPGet < Binstruct
#   string :op, 0, "Operation"
#   string :dir, 0, "Directory"
#   string :ver, 0, "Version"
#   
#   separator ' '
#   default_value :op, "GET"
#   default_value :dir, '/'
#   default_value :ver, "HTTP/1.0"
# end
#
#
# ---
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# Please read LICENSE.TXT for details. Or see RDoc for the file license.rb
class Binstruct
    attr_reader :parent, :children, :fields, :separator, :groups, :endianness
    attr_writer :fields, :separator

    # start Binstruct constructor / "meta" methods
    class << self
        attr_reader :parser_commands, :defaults, :friendly_values, :valid_values, :initial_separator_string, :initial_endianness
        attr_reader :grouped_fields
    end

    def self.new( *args, &blk ) #:nodoc:
        # default instance variables for the constructed class. DerivedClass.variable)
        # not object_of_derived_class.variable
        @defaults||={}
        @friendly_values||={}
        @valid_values||={}
        @parser_commands||=[]
        @grouped_fields||=Hash.new {|h,k| h[k]=[]}
        @initial_endianness||=:big
        super
    end

    # set up the field constructor methods
    def self.setup_field_builders(*fieldtypes) #:nodoc:
        fieldtypes.each {|fieldtype| 
            meta_def fieldtype do |*args|
                name, length, desc, condition=args
                condition||="true"
                @parser_commands||=[]
                @parser_commands << [fieldtype.to_s, name, length, desc, condition]
            end
        }
    end

    setup_field_builders *Fields::Field_Subtypes

    #Set default value for fields within a class.
    def self.default_value(sym, value)
        @defaults||={}
        @defaults[sym]=value
    end

    def self.fields_to_randomize #:nodoc:
        @fields_to_randomize||=[]
        @fields_to_randomize
    end

    #Randomize this field at instantiation (at bit level).
    def self.randomize( sym )
        fields_to_randomize << sym
    end

    # not fully implemented yet
    def self.friendly_values(sym, hash) 
        @friendly_values={}
        @friendly_values[sym]=hash
    end

    # not fully implemented yet
    def self.valid_values(sym, hash) 
        @valid_values={}
        @valid_values[sym]=hash
    end

    #Link sets of fields, such as type, length, value sets or length, data pairs. This
    #will create metadata that the Fuzzer can use to create nastier output.
    def self.group(sym, *other_syms)
        @grouped_fields||=Hash.new {|h,k| h[k]=[]}
        @grouped_fields[sym] << other_syms
    end

    #Define a separator string that will be used during the <tt>pack</tt> or <tt>to_s</tt> methods
    #for this structure. The separator will be inserted after every string but the last. The Fuzzer
    #will also use it by repeating the separator between fields. If a separator is set then calls to
    #Binstruct#new that have an argument (parser utilisation) will tokenize the string using the 
    #separator and ignore the length argument.
    def self.separator( separator_string )
        @initial_separator_string=String(separator_string)
    end

    def self.endianness( endianness )
        unless endianness.downcase==:big or endianness.downcase==:little
            raise ArgumentError, "Binstruct: Unknown endianness #{endianness}, use :little or :big (default)."
        end
        @initial_endianness=endianness
    end

    def self.method_missing( meth, *args ) #:nodoc:
        raise SyntaxError, "Binstruct: Unknown construction command: #{meth}"
    end

    #end Binstruct constructor methods

    # start Binstruct instance methods

    #With a buffer, parse the buffer according to the field definitions. Without a buffer, create a new
    #structure with all fields set to 0, '' or the default value.
    def initialize(buffer=nil)
        bitstring=buffer.unpack('B*').join unless buffer.nil?
        @children=[]
        @fields||=[]
        @parent=nil
        @separator=self.class.initial_separator_string || ''
        @endianness=self.class.initial_endianness
        @groups=self.class.grouped_fields
        self.class.parser_commands.each {|fieldtype, name, length, desc, condition|
            if eval condition
                default=self.class.defaults[name]
                field_class=Fields.const_get(fieldtype.capitalize+"Field")
                unless buffer.nil? # We're now parsing...
                    if @separator==''
                        #parse as packed binary
                        current_field=field_class.new(bitstring.slice!(0,(eval String(length))), name, (eval String(length)), desc, default,@endianness)
                    else
                        #parse as string tokens, using the separator
                        @tokens||=buffer.split(separator)
                        current_field=field_class.new((@tokens.shift.unpack('B*').join rescue ''), name, (eval String(length)), desc, default,@endianness)
                    end
                else # We're creating a default struct.
                    current_field=field_class.new('', name, (eval String(length)), desc, default,@endianness)
                    current_field.set_value(default) if default
                    current_field.randomize! if self.class.fields_to_randomize.any? {|sym| sym==name}
                end
                @fields << current_field
                @hash_references||={}
                @hash_references[name.to_sym]=current_field
                # add obj.fieldname and obj.fieldname= singleton methods to the object
                meta_def name do
                    current_field.get_value
                end
                meta_def (name.to_s+"=").to_sym do |new_val|
                    current_field.set_value(new_val)
                end
            end
        }
        @groups.each {|group, contents|
            unless contents.flatten.all? {|sym| @fields.any? {|field| field.name==sym}}
                raise RuntimeError, "Binstruct: Construction: group #{group} contains invalid field name(s)"
            end
        }
        # Shorten the input buffer to remove what we used. This is a bit spooky for structs that aren't byte aligned
        # but it's the best way I can think of. Remainders %8 will be packed according to their
        # integer value (so the leftover string "1111 1111 111" ends up as "\377\007"
        buffer.replace bitstring.scan(/.{8}/).map {|e| e.to_i(2).chr}.join unless buffer.nil?
    end

    #Reference a field directly by its symbol, returns the field object. 
    def []( sym )
        @hash_references[sym]
    end

    # Randomize a field. Returns the structure, unlike struct[:fieldname].randomize!
    # (which it uses internally).
    def randomize( sym )
        self[sym].randomize! # So either struct[:field].randomize! or struct.randomize :field will work
        self #this might be convenient sometimes, hence why there are two ways to do it.
    end


    #Add a child to the current Binstruct. The child must be a kind_of? Binstruct.
    def add_child( child )
        # should I allow user to shoot self in foot
        # by setting @children attr_writer - tree_run will
        # die etc as would all the length stuff... Let's not.
        raise ArgumentError, "Child not a Binstruct." unless child.kind_of? Binstruct
        child.instance_variable_set(:@parent,self)
        @children << child
    end

    #Delete a given child from the current Binstruct
    def remove_child( child )
        # wonder if I need fancy checking here... Can't see why.
        @children.delete( child ) && child.instance_variable_set(:@parent,nil)
    end

    #Boolean
    def has_children?
        not @children.empty?
    end

    #Boolean
    def has_parent?
        not @parent.nil?
    end

    #Length in bytes. Don't know if anyone would need length in
    #bits, but you could pull it by counting bitstring.length for
    #each field
    def length
        self.to_s.length 
    end

    #Same as to_s
    def pack
        self.to_s
    end

    #Packs everything up into a string. Will right pad the raw binary with '0' before packing if the structure is not byte aligned for some reason.
    def to_s
        # splice in the separators
        separated_fields=self.fields.inject( [] ) {|arr, elem| 
            arr.push self.separator unless arr.empty?
            arr.push elem
        }
        # empty separators vanish here
        bits=separated_fields.inject("") {|str,field| 
            field.kind_of?(Fields::Field) ?  str << field.bitstring : str << field.to_s.unpack('B*').join
        } 
        unless bits.length % 8 == 0
            puts "Warning, structure not byte aligned, right padding with 0"
        end
        bytearray=bits.scan(/.{1,8}/)
        bytearray << '0'*(8-bytearray.last.length) if bytearray.last.length < 8
        bytearray.map {|byte| "" << byte.to_i(2)}.join + @children.join
    end

    #Recursively run &block on this structure and every child within it.
    def tree_run( depth=0, &block)
        block.call(self, depth)
        @children.each {|child| child.tree_run(depth+1, &block)}
    end

    #Will dump the field description / field value pairs, although it's not very pretty. If the field array has been manually tampered with
    #(which people may want to do from time to time) it will just dump self.to_s.
    def inspect
        unless self.fields.all? {|field| field.kind_of? Fields::Field}
            # puts "Warning: fields manually altered, dumping raw string."
            return self.to_s
        end
        @fields.inject("") {|str, field| str << field.desc + ": " + String(field.get_value)+"\n"}
    end

    #Return a cloned object, recursing through children as neccessary
    def clone
        clonepuppy=self.class.new
        clonepuppy.clear_fields
        self.fields.each {|field|
            # this replicates most of the initialize functionality, but we can't
            # use initialize by dumping out the string, because of variable length
            # fields. The initialize method will greedily fill variable fields which
            # might have been left empty during manual construction.
            field_copy=field.deep_copy
            clonepuppy.fields << field_copy
            clonepuppy.add_hash_ref field_copy
            clonepuppy.instance_eval do
                meta_def field.name do
                    field_copy.get_value
                end
                meta_def (field.name.to_s+"=").to_sym do |new_val|
                    field_copy.set_value new_val
                end
            end

        }
        if self.has_parent?
            clonepuppy.instance_variable_set :@parent, self.parent
            #the results for cloning a structure that isn't the top level in the
            # child parent tree is probably a little undefined, but let's allow it
            # for now.
        end
        while clonepuppy.has_children?
            clonepuppy.remove_child clonepuppy.children.first
        end
        self.children.each {|child|
            clonepuppy.add_child child.clone
        }       
        clonepuppy
    end

    protected

    def add_hash_ref( field )
        @hash_references||={}
        @hash_references[field.name]=field
    end

    def clear_fields
        @fields.replace []
    end

    # end Binstruct instance methods

end
