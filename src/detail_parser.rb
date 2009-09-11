# Some code to parse crash detail files, mainly focused on the machine
# parseable output of !exploitable.
module DetailParser

    # In: the entire detail file as a string
    # Out: [[0, "wwlib!wdCommandDispatch+0x14509b"], [1, ... etc
    def self.stack_trace( detail_string )
        frames=detail_string.scan( /STACK_FRAME:(.*)$/ ).flatten
        (0..frames.length-1).to_a.zip frames
    end

    # In: The entire detail file as a string
    # Out: Array of name, version, hash.
    # [["wwlib", "1.2.1511", "5ef6ff4", ["mso.dll ... etc
    def self.loaded_modules( detail_string )

    end

    # In: the entire detail file as a string
    # Out: [[0, "316c5a0e mov eax,dword ptr [eax]"], [1, 
    def self.disassembly( detail_string )
        instructions=detail_string.scan( /BASIC_BLOCK_INSTRUCTION:(.*)$/ ).flatten
        (0..instructions.length-1).to_a.zip instructions
    end

    # In: the entire detail file as a string
    # Out: [["eax", "00000000"], ["ebx", ... etc
    def self.registers( detail_string )
        # *? is non-greedy, m is multiline. We take the last register string 
        # because the first one is from the initial breakpoint.
        detail_string.scan(/^eax.*?iopl/m).last.scan(/(e..)=([0-9a-f]+)/)
    end

    # In: the entire detail file as a string
    # Out: Long bug description, eg "Data from Faulting Address controls
    # Branch Selection"
    def self.long_desc( detail_string )
        detail_string.match(/^DESCRIPTION:(.*)$/)[1]
    end

    # In: the entire detail file as a string
    # Out: !exploitable classification, "UNKNOWN", "PROBABLY EXPLOITABLE" etc
    def self.classification( detail_string )
        detail_string.match(/^CLASSIFICATION:(.*)$/)[1]
    end

    # In: the entire detail file as a string
    # Out: !exploitable exception type, "STATUS_ACCESS_VIOLATION" etc
    def self.exception_type( detail_string )
        detail_string.match(/^EXCEPTION_TYPE:(.*)$/)[1]
    end

    # In: the entire detail file as a string
    # Out: !exploitable exception subtype, "READ" or "WRITE" etc
    def self.exception_subtype( detail_string )
        detail_string.match(/^EXCEPTION_SUBTYPE:(.*)$/)[1]
    end

    # In: the entire detail file as a string
    # Out: !exploitable Hash as a string eg "0x6c4b4441.0x1b792103"
    def self.hash( detail_string )
        detail_string.match(/Hash=(.*)\)/)[1]
    end

end
