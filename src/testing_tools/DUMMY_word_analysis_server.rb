require File.dirname(__FILE__) + '/analysis_server'
require File.dirname(__FILE__) + '/analysis_fsconn'
require 'base64'

# This is dummy code, used for debugging speed problems.
# Revised version, using v2 of the fuzzprotocol.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt


class FuzzServerConnection < HarnessComponent
    # Dummy code - replace the DB inserts with a simple counter.
    # We leave the setup (new template etc) DB inserts, and we really do connect 
    # to the DB etc, so only the inserts are dummied.
    def handle_test_result( msg )
cancel_idle_loop
        @fake_dbid||=0
        template_hash, result_string=msg.template_hash, msg.status
        if result_string=='crash'
            crash_file=Base64::decode64( msg.crashfile )
            if Zlib.crc32(crash_file)==msg.crc32
                crash_data=Base64::decode64( msg.crashdata )
                db_id=(@fake_dbid+=1)
                add_to_trace_queue( msg.crashfile, template_hash, db_id, crc32)
                send_ack( msg.ack_id, 'db_id'=>db_id )
            end
        else
            db_id=(@fake_dbid+=1)
            send_ack( msg.ack_id, 'db_id'=>db_id )
        end
        start_idle_loop( 'verb'=>'db_ready' )
    end
end

EM.epoll
EM.set_max_timers(50000000)
EventMachine::run {
    # Anything not set up here gets the default value.
    AnalysisServer.setup(
        'debug'=>true, 
        'server_ip'=>'192.168.242.101',
        'poll_interval'=>50
)
EventMachine::start_server(AnalysisServer.listen_ip, AnalysisServer.listen_port, AnalysisServer)
}
