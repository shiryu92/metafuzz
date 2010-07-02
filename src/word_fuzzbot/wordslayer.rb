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

def kill_this( pid )
    begin
        hprocess=Windows::Process::OpenProcess.call(Windows::Process::PROCESS_TERMINATE,0,pid)
        Windows::Process::TerminateProcess.call(hprocess,1)
        true
    rescue
        false
    end
end

def kill_explorer(wmi)
    processes=wmi.ExecQuery("select * from win32_process where name='explorer.exe'")
    processes.each {|p|
        kill_this p.ProcessId
    }
    processes=nil
end

def poke_cdb( wmi )
    processes=wmi.ExecQuery("select * from win32_process where name='cdb.exe'")
    processes.each {|p|
        Process.kill(1,p.ProcessId)
    }
    processes=nil
end


def delete_tests
    begin
        Dir.glob('R:/fuzzclient/*.doc', File::FNM_DOTMATCH).each {|fn| 
            FileUtils.rm_f( fn ) rescue nil
            print "$";$stdout.flush
        }
    rescue
        return
    end
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

def age_of_newest_file( pattern )
    (Dir.glob( pattern, File::FNM_DOTMATCH ).map {|fn| Time.now - File.ctime( fn )}.min) || 0
end

word_instances=Hash.new(0)
word_procs=[]
wmi = WIN32OLE.connect("winmgmts://")
FileUtils.mkdir_p 'R:/Temp'
begin
    kill_explorer( wmi )
    loop do
        begin
            word_procs=get_process_array(wmi)
            word_instances.delete_if {|pid,seen_count| not word_procs.include?(pid)}
        rescue
            nil
        end
        word_procs.each {|p| word_instances[p]+=1}
        word_instances.each {|pid,seen_count|
            next unless pid
            if seen_count > 25 # this will also clean up old duplicate processes
                kill_this( pid )
                print "<#{pid}>";$stdout.flush
            end
            if seen_count > 150
                poke_cdb( wmi )
                print "[!!!]";$stdout.flush
            end
        }
        if age_of_newest_file( "R:/fuzzclient/*.doc" ) > 20 
            # killing spree!
            word_instances.each {|pid,seen_count|
                next unless pid
                if seen_count <= 25
                    Process.kill(1, pid) rescue nil # opens a thread and sends exitprocess
                    print "[#{pid}]";$stdout.flush
                end
                word_instances[pid]+=25
            }
            delete_tests
        end
        print '*';$stdout.flush
        sleep(5)
        delete_temp_files
    end
rescue Exception => e
    puts "Wordslayer: PK: #{$!}"
    puts e.backtrace
    sleep(1)
    retry
end
