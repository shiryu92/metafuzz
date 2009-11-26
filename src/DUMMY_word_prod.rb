require 'rubygems'
require 'fuzzer'
require 'wordstruct'
require 'ole/storage'

class Producer < Generators::NewGen

	START_AT=0

	Template=File.open( File.expand_path("~/fuzzserver/boof.doc"),"rb") {|io| io.read}

	def seen?( str )
		hsh=Digest::MD5.hexdigest(str)
		seen=@duplicate_check[hsh]
		@duplicate_check[hsh]=true
		@duplicate_check.shift if @duplicate_check.size > SEEN_LIMIT
		seen
	end

	def initialize
		@duplicate_check=Hash.new(false)
		@block=Fiber.new do
			begin
				loop do
					Fiber.yield Template
					sleep 0.01
				end
			rescue
				puts "Production failed: #{$!}";$stdout.flush
				exit
			end
			false
		end
		super
	end
end
