require 'rubygems'
require 'trollop'

OPTS=Trollop::options do 
    opt :bitlength, "Bitlength for change masks", :type => :integer, :required => true
    opt :stepsize, "Bits to advance each step", :type => :integer, :required => true
    opt :length, "Total length of bitstring", :type => :integer, :required => true
end

def create_masks(len, stepsize, bitlength)
    final_cases=[]
    (0..len).step(stepsize) {|idx|
        left_part="0" * idx
        this_idx_cases=[]
        (0..(2**bitlength)-1).each {|int|
            mask="%-#{bitlength}.#{bitlength}b" % int
            this_case=(left_part + mask + ("0" * len)).slice(0,len)
            this_idx_cases << this_case
        }
        final_cases+=(this_idx_cases.uniq)
    }
    final_cases.uniq
end

create_masks(OPTS[:length], OPTS[:stepsize], OPTS[:bitlength]).each {|mask|
    str=[mask].pack('B*')
    puts str.unpack("H*").first.scan(/.{2}/).map {|s| "\\x#{s}"}.join
}
