require File.dirname(__FILE__) + '/../core/binstruct'

class TRACE_RECORD_DIRECT_CALL < Binstruct
    def self.reclen( arch )
        arch * 3
    end
    def initialize( buf, arch, &blk )
        @arch=arch
        @reclen=arch * 3
        super( buf, &blk )
    end
    parse {|buf|
        endian :little
        unsigned buf, :address, @arch, "Address of CALL"
        unsigned buf, :target, @arch, "Target address"
        unsigned buf, :esp, @arch, "ESP"
    }
end
class TRACE_RECORD_INDIRECT_CALL < Binstruct
    def self.reclen( arch )
        arch * 3
    end
    def initialize( buf, arch, &blk )
        @arch=arch
        @reclen=arch * 3
        super( buf, &blk )
    end
    parse {|buf|
        endian :little
        unsigned buf, :address, @arch, "Address of Indirect CALL"
        unsigned buf, :target, @arch, "Target address"
        unsigned buf, :esp, @arch, "ESP"
    }
end

class TRACE_RECORD_RETURN < Binstruct
    def self.reclen( arch )
        arch * 3
    end
    def initialize( buf, arch, &blk )
        p "in init"
        @arch=arch
        @reclen=arch * 3
        super( buf, &blk )
    end
    parse {|buf|
        endian :little
        p "in parse"
        unsigned buf, :address, @arch, "Address of RET"
        unsigned buf, :retval, @arch, "Retval"
        unsigned buf, :esp, @arch, "ESP"
    }
end

class TRACE_RECORD_BASIC_BLOCK < Binstruct
    def self.reclen( arch )
        arch
    end
    def initialize( buf, arch, &blk )
        @arch=arch
        @reclen=arch
        super( buf, &blk )
    end
    parse {|buf|
        endian :little
        unsigned buf, :address, @arch, "Basic Block Address"
    }
end

class TRACE_RECORD_HEAP_ALLOC < Binstruct
    def self.reclen( arch )
        arch + 96
    end
    def initialize( buf, arch, &blk )
        @arch=arch
        super( buf, &blk )
    end
    parse {|buf|
        endian :little
        unsigned buf, :heap, 32, "Heap handle"
        unsigned buf, :size, 64, "Alloc size"
        unsigned buf, :address, @arch, "Heap Address"
    }
end

class TRACE_RECORD_HEAP_REALLOC < Binstruct
    def self.reclen( arch )
        arch + 96
    end
    def initialize( buf, arch, &blk )
        @arch=arch
        super( buf, &blk )
    end
    parse {|buf|
        endian :little
        unsigned buf, :heap, 32, "Heap handle"
        unsigned buf, :size, 64, "Alloc size"
        unsigned buf, :address, @arch, "Heap Address"
    }
end

class TRACE_RECORD_HEAP_FREE  < Binstruct
    def self.reclen( arch )
        96
    end
    def initialize( buf, arch, &blk )
        @arch=arch
        super( buf, &blk )
    end
    parse {|buf|
        endian :little
        unsigned buf, :heap, 32, "Heap handle"
        unsigned buf, :address, @arch, "Heap Address"
    }
end

class TRACE_RECORD_MEMORY < Binstruct
    def self.reclen( arch )
        arch*2 + 32
    end
    def initialize( buf, arch, &blk )
        @arch=arch
        super( buf, &blk )
    end
    parse {|buf|
        endian :little
        unsigned buf, :address, @arch, "Address"
        unsigned buf, :store, 32, "Store"
        unsigned buf, :target, @arch, "Target"
    }
end

class TRACE_RECORD_NONE < Binstruct
end


class TraceRecord < Binstruct

    TRACE_RECORD_TYPES={
        0=>TRACE_RECORD_NONE,
        1=>TRACE_RECORD_INDIRECT_CALL,
        2=>TRACE_RECORD_DIRECT_CALL,
        3=>TRACE_RECORD_RETURN,
        4=>TRACE_RECORD_BASIC_BLOCK,
        5=>TRACE_RECORD_HEAP_ALLOC,
        6=>TRACE_RECORD_HEAP_REALLOC,
        7=>TRACE_RECORD_HEAP_FREE,
        8=>TRACE_RECORD_MEMORY
    }
    def initialize( buf, arch, &blk )
        @arch=arch
        super( buf, &blk )
    end

    parse {|buf|
        endian :little
        unsigned buf, :type, 32, "TraceRecord Type"
        unsigned buf, :threadid, 32, "Thread ID for this record"
        subklass=TRACE_RECORD_TYPES[self.type]
        substruct( buf, :contents, subklass.reclen( @arch ), subklass, @arch )
    }
end
