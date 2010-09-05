require 'open3'

$stdout.sync
  stdin, stdout, stderr, wait_thr = Open3.popen3("cmd")
  pid = wait_thr[:pid]  # pid of the started process.
  p pid
  Thread.new do
      loop do
      print stdout.read(1)
      end
  end
  stdin.write "dir\n"
  stdin.write "ver\n"
  sleep 5
  stdin.close  # stdin, stdout and stderr should be closed in this form.
  stdout.close
  stderr.close
  exit_status = wait_thr.value  # Process::Status object returned.
  p exit_status

  require '../core/connector'
  require 'conn_cmd'
  cmd=Connector.new(CONN_CMD)
  cmd.puts "dir"
  sleep 0.1
  puts cmd.dq_all.join
  cmd.puts "ver"
  sleep 0.1
  puts cmd.dq_all.join
