class ListNode

    attr_accessor :next, :prev, :value, :guard, :tag

    def initialize( val=nil, guard=false )
        @value=val
        @next=@prev=self
        @guard=guard
        @value="G" if guard
        # Rules like to know what containers they are in.
        if val.respond_to? :containers
            val.containers << self
        end
    end

    def is_guard?
        @guard
    end

    def destroy
        if @value.is_a? Rule
            @value.containers.delete self
            @value.check_utility
        end
        @value=nil
        #@next=@prev=nil
    end

    def inspect
        "#{@prev.value.inspect rescue prev.inspect}<-#{@value.inspect}(R#{tag})"
    end

end
