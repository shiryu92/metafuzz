require 'esx_host'

target_hosts=[]
(125..132).each {|i|
	host=ESXHost.new("10.254.254.#{i}")
	target_hosts << host
}

source_host=ESXHost.new("10.254.254.128") # main source
source_dir="/vmfs/volumes/datastore2/fc-base"
counter=0

target_hosts.each {|target|
	if target.datastores.length == 1
		# 8 clones in this DS
		puts "8 clones in #{target.address} in #{target.datastores.first}"
		8.times do
			source_host.clone(
				source_dir,
				target,
				target.datastores.first,
				"clone-#{counter}"
			)
			counter+=1
		end
	elsif target.datastores.length == 4
		if target.address==source_host.address
			# 2 in each
			puts "8 clones in #{target.address}"
			target.datastores.each {|ds|
				2.times do
					source_host.clone(
						source_dir,
						target,
						ds,
						"clone-#{counter}"
					)
					counter+=1
				end
			}
		else
			# 4 clones in each
			puts "16 clones in #{target.address}"
			target.datastores.each {|ds|
				4.times do
					source_host.clone(
						source_dir,
						target,
						ds,
						"clone-#{counter}"
					)
					counter+=1
				end
			}
		end
	else
		raise RuntimeError "Target stores messed up? #{$!}"
	end
}
