# I suspect I stole some of this code, but I can't remember where from, sorry.
# In any case, it needed lots of modification to work with EventMachine.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class NetStringTokenizer
    BadStringError = Class.new(StandardError)
    InvalidDataLengthError = Class.new(BadStringError)
    LengthMismatchError = Class.new(BadStringError)
    UnterminatedStringError = Class.new(BadStringError)
    LengthLimitExceedError = Class.new(BadStringError)

    # 0 upto 99999999 bytes (96 MB)
    LENGTH_DIGITSNUM_RANGE = (1..8)
    def initialize
        @input="" # The idea is that @input is persistent over multiple calls to parse.
    end

    def parse(data)
        entities=[]
        @input << data
        while @input
            begin
                len,data=@input.split(":",2)
                raise InvalidDataLengthError unless (LENGTH_DIGITSNUM_RANGE === len.length)
                data_length=Integer(len) rescue raise(InvalidDataLengthError)
                return entities unless data # no data yet, give execution back to the caller.
                if data.length==data_length+1 # Correct length, check for termination
                    raise UnterminatedStringError unless data[-1] == ?,
                    # All should be well!
                    entities << data.chop
                    @input=""
                    return entities
                elsif data.length > data_length+1 # Overlap or unterminated
                    raise UnterminatedStringError unless data[data_length] == ?,
                    entities << data[0,data_length]
                    @input=data[data_length+1..-1] # Deal with the extra bit next time round
                else
                    # data not yet complete
                    return entities
                end
            rescue
                @input=""
                # should we raise an exception? We'd lose
                # all the current entities in the array...
                return entities
            end
        end
    end

    def flush
        truncated=@input
        @input=""
        truncated
    end

    def pack(str)
        str = str.to_s
        "#{str.size}:#{str},"
    end
end
