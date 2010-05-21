require 'json'

class DynRIODump
    def initialize( filename )
        @fh=File.open(filename, "rb")
    end

    # This is not really optimal for random access
    # to the "records", but it should be good enough for 
    # sequential access, which is what I expect to use
    # most of the time.
    def get_record( num )
        current=@fh.lineno
        if num < current
            @fh.rewind 
            current=0
        end
        (num - current).times do
            @fh.gets
        end
        JSON.parse @fh.readline
    end
end

class SequiturDump
    attr_reader :old, :new, :grammar
    def initialize( filename )
        begin
            fh=File.open( filename, "rb" )
            rawseq=fh.readline.split(/0 -> (.*) &1234567890 (.*) /)
            @old=rawseq[1].split
            @new=rawseq[2].split
            unless @old.length > 1 && @new.length > 1
                raise RuntimeError, "Sequitur Dump: sequence(s) don't seem long enough?"
            end
            @grammar={}
            fh.read.scan(/(.*) -> (.*) /).each {|rulenum, rule|
                grammar[rulenum.to_i]=rule.split.map {|e| Integer(e) rescue e}
            }
        ensure
            fh.close
        end
    end

    def expand_rule( rule_num, level_limit=-1, level=0 )
        @grammar[Integer(rule_num)].map {|e|
            if e.is_a?( Integer ) && (level_limit==-1 || level < level_limit)
                expand_rule( e, level_limit, level+1 )
            else
                e
            end
        }.flatten
    end

    def inspect
        "#{@grammar.size} grammar, old seq #{@old.length}, new seq #{@new.length}"
    end
end


