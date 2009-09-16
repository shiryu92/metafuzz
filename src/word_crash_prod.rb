require File.dirname(__FILE__) + '/generators'

class Producer < Generators::NewGen

    Template=File.open( File.expand_path("crash-OFELS-4359104.doc"),"rb") {|io| io.read}

    def initialize
        @duplicate_check=Hash.new(false)
        @block=Fiber.new do
            loop do
                Fiber.yield Template
            end
            false
        end
        super
    end
end
