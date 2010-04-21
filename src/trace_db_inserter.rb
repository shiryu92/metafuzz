require File.dirname(__FILE__) + '/trace_db_api'
require 'rubygems'
require 'trollop'
require 'JSON'

OPTS = Trollop::options do 
    opt :db, "URL of database (postgres://host_name/db_name)", :type => :string
    opt :username, "Postgres username", :type => :string
    opt :password, "Postgres password", :type => :string
    opt :filename, "Raw dump filename", :type => :string
end

DB=MetafuzzDB::TraceDB.new(OPTS[:db], OPTS[:username], OPTS[:password])
TraceID=DB.new_trace( OPTS[:filename] )

def handle_line( json_line )
    line=JSON.parse( json_line )
    if line["type"]=="module"
        DB.add_module( TraceID, line )
    else
        DB.append_entry( TraceID, line )
    end
end

File.open(OPTS[:filename], "rb") {|fh|
    handle_line(fh.readline) until fh.eof?
    DB.flush
}
