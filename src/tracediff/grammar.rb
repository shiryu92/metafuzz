class Grammar
    def initialize( filename, mode=:lines )
        begin
            fh=File.open( filename, "rb" )
            @grammar={}
            fh.read.scan(/(.*) -> (.*) /).each {|rulenum, rule|
                @grammar[rulenum.to_i]=rule.split.map {|e| 
                    begin
                        Integer(e)
                    rescue
                        if mode==:lines
                            e # original symbols start with &
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
        unless rule_num.is_a? Integer and rule_num < @grammar.size
            return rule_num
        end
        final=[]
        stack=[[rule_num, level_limit, level]]
        until stack.empty?
            tok, lim, lev=stack.pop
            if tok.is_a?( Integer ) && (lim==-1 || lev <= lim)
                @grammar[Integer( tok )].reverse.each {|tok|
                    stack.push [tok, lim, lev+1]
                }
            else
                final.push tok
            end
        end
        final
    end

    def []( index )
        @grammar[index]
    end

    def inspect
        "#{@grammar.size} rules in grammar"
    end
end
