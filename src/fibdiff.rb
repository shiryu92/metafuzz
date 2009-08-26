require 'binstruct'
require 'fib'

begin
    orig_file=ARGV[0]
    corrupt_file=ARGV[1]
    orig_data=IO.read(orig_file,1472,512)
    corrupt_data=IO.read(corrupt_file,1472,512)
    original=WordFIB.new(orig_data)
    corrupt=WordFIB.new(corrupt_data)
    original.fields.each_index {|field_index|
        unless original.fields[field_index].get_value==corrupt.fields[field_index].get_value
            puts original.fields[field_index].desc
            puts "Original #{original.fields[field_index].name} - #{original.fields[field_index].get_value} -> Corrupt - #{corrupt.fields[field_index].get_value}"
        end
    }
rescue
    puts "Usage: fibdiff original_file corrupt_file"
end

