require 'rubygems'
require 'win32/process'
require 'win32ole'
require 'fileutils'

# Some fairly quick and dirty code to kill off stale word processes
# and clean up temp files. Runs while the fuzzer is running.
#
# You can adjust the sleep time to have it be more aggressive in killing
# old processes, but you risk killing things that might be halfway through
# crashing.
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

def get_process_array(wmi)
    # This looks clumsy, but the processes object doesn't support #map. :)
    processes=wmi.ExecQuery("select * from win32_process where name='WINWORD.EXE'")
    ary=[]
    processes.each {|p|
        ary << p.ProcessId
    }
    processes=nil
    ary
end

def delete_temp_files
        patterns=['R:/Temp/**/*.*', 'R:/Temporary Internet Files/**/*.*', 'R:/fuzzclient/~$*.doc']
        patterns.each {|pattern|
        Dir.glob(pattern, File::FNM_DOTMATCH).each {|fn|
            next if File.directory?(fn)
            begin
                FileUtils.rm_f(fn)
            rescue
                next # probably still open
            end
            print "@";$stdout.flush
        }
        }
end

word_instances=Hash.new(0)
wmi = WIN32OLE.connect("winmgmts://")
FileUtils.mkdir_p 'R:/Temp'
begin
    loop do
        procs=get_process_array(wmi)
        word_instances.delete_if {|pid,seen_count| not procs.include?(pid)}
        procs.each {|p| word_instances[p]+=1}
        word_instances.each {|pid,seen_count|
            if seen_count > 1 # seen before, try and kill
                Process.kill(9,pid)
                print "<#{pid}>";$stdout.flush
            end
        }
        print '*';$stdout.flush
        sleep(10)
        delete_temp_files
    end
rescue
    puts "Wordslayer: PK: #{$!}"
    sleep(1)
    retry
end