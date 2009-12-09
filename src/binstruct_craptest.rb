require 'rubygems'
require 'zlib'
require 'binstruct'
require 'wordstruct'
require 'ole/storage'
Template=File.open("../fuzzserver/dgg.doc","rb") {|io| io.read}
old=Time.now
10.times do
	unmodified_file=StringIO.new(Template.clone)
	header=unmodified_file.read(512)
	raw_fib=unmodified_file.read(1472)
	rest=unmodified_file.read
	raise RuntimeError, "Data Corruption" unless header+raw_fib+rest == Template
	fib=WordStructures::WordFIB.new(raw_fib.clone)
	raise RuntimeError, "Data Corruption - fib.to_s not raw_fib" unless fib.to_s == raw_fib
	# Open the file, get a copy of the table stream
	unmodified_file.rewind
	ole=Ole::Storage.open(unmodified_file)
	# get the correct table stream 1Table or 0Table
	table_stream=ole.file.read(fib.fWhichTblStm.to_s+"Table")
	ole.close
	fc=:fcDggInfo
	lcb=:lcbDggInfo
	#get the head, fuzztarget and rest from the table stream
	ts_head=table_stream[0,fib.send(fc)]
	fuzztarget=table_stream[fib.send(fc),fib.send(lcb)]
	ts_rest=table_stream[fib.send(fc)+fib.send(lcb)..-1]
	raise RuntimeError, "Data Corruption - TS corrupt" unless (ts_head+fuzztarget+ts_rest)==table_stream
	raise RuntimeError, "Data Corruption - LCB / fuzztarget length mismatch" unless fib.send(lcb)==fuzztarget.length
	begin
		dgg_parsed=[]
		fuzzcopy=fuzztarget.clone
		while fuzzcopy.length > 0
			dgg_parsed << WordStructures::WordDgg.new(fuzzcopy)
			if fuzzcopy.length > 0
				dgg_parsed << Binstruct.new(fuzzcopy.slice!(0,1)) {|buf| unsigned buf, :foo, 8, "thing"}
			end
		end
	rescue
		raise RuntimeError, "DggFuzz: #{$!}"
	end
	raise RuntimeError, "Data Corruption - Binstruct.to_s not fuzztarget" unless dgg_parsed.join == fuzztarget
end
puts Time.now - old
