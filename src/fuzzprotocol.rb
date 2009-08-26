require 'objhax'
require 'json'
require 'digest/md5'

# This class just handles the serialization, the mechanics of the protocol itself
# is "defined" in the FuzzClient / FuzzServer implementations. It is very lazy
# which allows the protocol to be changed by simply changing the code at each peer.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class FuzzMessage

    # .new can take a Hash or YAML-dumped Hash, and any symbols not defined 
    # below will also be added as getters and setters, making the protocol
    # self extending if both parties agree.
    def initialize(data)
        if data.class==String
            load_json(data)
        else
            unless data.class==Hash
                raise ArgumentError, "FuzzMessage: .new takes a Hash or a JSON-dumped Hash."
             end
            @msghash=data
        end
        # Set up instance getters and setters for the hash symbols
        @msghash.each {|k,v|
            meta_def String(k) do
                @msghash[k]
            end

            meta_def (String(k)+'=') do |new_val|
                @msghash[k]=new_val
            end
        }
            
    end

    def to_hash
        @msghash
    end

    def load_json(json_data)
        begin
            decoded=JSON::load(json_data)
            unless decoded.class==Hash
                raise ArgumentError, "FuzzMessage (load_json): JSON data not a Hash!"
            end
            @msghash=decoded
        rescue
            raise ArgumentError, "FuzzMessage (load_json): Bad JSON data."
        end
    end

    def to_s
        @msghash.to_json
    end
end
