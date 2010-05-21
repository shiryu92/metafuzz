require 'rubygems'
require 'ramaze'
require 'json'
require 'rtdbwrapper'
require 'fileutils'

# This is a (very) quick webserver that allows the client to query
# the results DB via a REST style interface  at 
# http://<server>/result/23356 etc etc. The intention was to allow
# adaptive fuzzing by building production clients that would modify
# their behaviour based on the results of each test, but I don't
# do my case generation that way, myself. Might be dusted off and
# improved, one of these days.
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

FileUtils.copy("/dev/shm/metafuzz.db", "/dev/shm/metafuzz_ro.db")
DB=RTDB.new("/dev/shm/metafuzz_ro.db")

class MainController < Ramaze::Controller
    def index
        FileUtils.copy("/dev/shm/metafuzz.db", "/dev/shm/metafuzz_ro.db")
        s=DB.result_summary
        "Results at #{Time.now} - Total Results - #{s[:total]}<br>
        Success: #{s[:success]}, Fail: #{s[:fail]}, Crash: #{s[:crash]}<br>
        Currently at #{s[:speed]}/sec"
    end

    def result(id)
        FileUtils.copy("/dev/shm/metafuzz.db", File.expand_path("~/fuzzserver/metafuzz.db"))
        DB.result_for_id(id).to_json
    end
    def crashdetail(id)
        FileUtils.copy("/dev/shm/metafuzz.db", "/dev/shm/metafuzz_ro.db")
        path=DB.crashdetail_for_id(id)
        File.open(path, "r") {|io| io.read} rescue $!
    end
    def crashfile(id)
        FileUtils.copy("/dev/shm/metafuzz.db", "/dev/shm/metafuzz_ro.db")
        path=DB.crashfile_for_id(id)
        contents=File.open(path,"rb") {|io| io.read} rescue nil
        if contents
            respond(contents,200,'Content-Type'=>"application/msword",
                'Content-Disposition'=>%(attachment; filename="#{File.split(path).last}"))
        else
            $!
        end
    end

end

Ramaze.start
