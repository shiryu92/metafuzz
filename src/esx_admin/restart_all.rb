require 'esx_host'

target_hosts=[]
(125..132).each {|i|
	host=ESXHost.new("10.254.254.#{i}")
	target_hosts << host
}

target_hosts.each {|host|
	host.poweroff_vms {|vm| vm.name =~ /clone-\d+/}
	sleep 60
	host.poweron_vms {|vm| vm.name =~ /clone-\d+/}
}

