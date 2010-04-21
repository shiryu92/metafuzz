class Grammar
    def initialize( filename, mode=:lines )
        begin
            fh=File.open( filename, "rb" )
            @grammar={}
            fh.read.scan(/(.*) -> (.*) /).each {|rulenum, rule|
                # This is a bit specific, we assume that rules are integers
                # and tokens are strings, but we strip any leading '&'
                @grammar[rulenum.to_i]=rule.split.map {|e| 
                    begin
                        Integer(e)
                    rescue
                        if mode==:lines
                            e[1..-1]
                        else
                            e.sub!('\\n',"\n")
                            e.tr!('_',' ')
                            e
                        end
                    end
                }
            }
        rescue
            raise RuntimeError, "Grammar: Unable to initialize. #{$!}"
        ensure
            fh.close rescue nil
        end
    end

    def size
        @grammar.size
    end

    def expand_rule( rule_num, level_limit=-1, level=0 )
        final=[]
        @grammar[Integer(rule_num)].each {|e|
            if e.is_a?( Integer ) && (level_limit==-1 || level < level_limit)
                final.push *(expand_rule( e, level_limit, level+1 ))
            else
                final.push e
            end
        }
        final
    end

    def []( index )
        @grammar[index]
    end

    def inspect
        "#{@grammar.size} rules in grammar"
    end
end
