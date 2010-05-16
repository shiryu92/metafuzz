require 'esx_host'

target_hosts=[]
(125..132).each {|i|
	host=ESXHost.new("10.254.254.#{i}")
	target_hosts << host
}

target_hosts.each {|host|
	clones=host.vms.select {|vm| vm.name =~ /clone-\d+/}
	clones.each {|clone|
		vmx=clone.file
		host.sc "sed -i \"s/PlayNet/FuzzNet/g\" #{vmx}"
	}
}

