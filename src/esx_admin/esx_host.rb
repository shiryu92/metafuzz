require 'objhax'

class ESXVM
	attr_reader :host
	def initialize( parent_host, hsh )
		@host=parent_host
		hsh.each {|k,v|
			meta_def k do v end
		}
	end

	def poweroff
		@host.sc "vim-cmd vmsvc/power.off #{vmid}"
	end

	def poweron
		@host.sc "vim-cmd vmsvc/power.on #{vmid}"
	end

	def unregister
		@host.sc "vim-cmd vmsvc/unregister #{vmid}"
	end

	def register
		@host.sc "vim-cmd solo/registervm #{config_file}"
	end

end

class ESXHost
	attr_reader :address
	def initialize( host )
		@address=host
	end

	def send_command( str )
		out=`ssh root@#{@address} "#{str}"`
	end
	alias :sc :send_command

	def datastores
		@datastores||=send_command("ls /vmfs/volumes/datastore*").split
	end

	def poweron_vms( &blk )
		self.vms.select(&blk).each {|vm| vm.poweron}
	end

	def poweroff_vms( &blk )
		self.vms.select(&blk).each {|vm| vm.poweroff}
	end

	def clone( source_dir, dest_host, dest_datastore, new_name)
		# construct the clone locally
		puts "Constructing clone..."
		base, name=File.split(source_dir)
		# if possible, put the work dir in a different datastore
		# (if there is only one datastore, index 0 becomes -1
		# which is the same)
		work_base=datastores[(datastores.index(base))-1]
		working="#{work_base}/temp"
		sc "rm -rf #{working}"
		sc "mkdir #{working}"

		# Clone the disk locally
		puts "Cloning disk..."
		source_disk="#{source_dir}/#{name}.vmdk"
		dest_disk="#{working}/#{new_name}.vmdk"
		source_vmx="#{source_dir}/#{name}.vmx"
		dest_vmx="#{working}/#{new_name}.vmx"
		sc "vmkfstools -i #{source_disk} #{dest_disk}"

		# Copy and modify the VMX config_file
		puts "Modifying VMX config_file.."
		sc "cp #{source_vmx} #{dest_vmx}"
		sc "sed -i \"s/#{name}/#{new_name}/g\" #{dest_vmx}"
		sc "sed -i \"/uuid/d\" #{dest_vmx}"
		sc "sed -i \"/generatedAddress/d\" #{dest_vmx}"
		sc "echo uuid.action = \"create\" >> #{dest_vmx}"

		# copy the directory to the destination
		puts "Copying to destination..."
		dest_dir="#{dest_datastore}/#{new_name}"
		unless dest_host.address==@address
			sc "scp -i /.ssh/id_rsa.db -r #{working} root@#{dest_host.address}:#{dest_dir}"
		else
			sc "cp -R #{working} #{dest_dir}"
		end

		# clean up the work dir
		sc "rm -rf #{working}"
		#
		# register it
		puts "Registering clone..."
		dest_host.sc "vim-cmd solo/registervm #{dest_dir}/#{new_name}.vmx"
		puts "Done!"
	end

	def vms
		raw=sc "vim-cmd vmsvc/getallvms"
		ary=raw.split("\n")
		ary.each {|e| e.squeeze!(' ');e.strip!}
		ary.shift # header line
		vmary=[]
		ary.each {|l|
			a=l.split(' ')
			hsh={}
			hsh[:vmid]=a[0]
			hsh[:name]=a[1]
			datastore="/vmfs/volumes/" << a[2].tr('[]','') << "/" << a[3]
			hsh[:config_file]=datastore
			hsh[:guest_os]=a[4]
			hsh[:version]=a[5]
			vmary << hsh
		}
		vmary.map {|hsh| ESXVM.new(self, hsh)}
	end

	def file_exists?( fname )
		result=send_command "if [ -e #{fname} ];then echo yes;fi"
		result.strip=="yes"
	end

end
