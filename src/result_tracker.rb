require File.dirname(__FILE__) + '/rtdbwrapper'

# Just a quick wrapper, so I can change the underlying DB.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class ResultTracker

    def initialize(dbfile)
        @production_clients=0
        @fuzz_clients=0
        @db=RTDB.new(dbfile)
    end

    def add_result(id, status, crashdetail_path=nil,crashfile_path=nil)
        @db.insert_result(id,status.to_sym,crashdetail_path,crashfile_path)
    end

    def results_outstanding
        @db.results_outstanding
    end

    def check_out
        @db.check_out
    end

    def summary
        @db.summary
    end
end
