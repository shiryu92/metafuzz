require 'rubygems'
require 'sequel'

# This is a fairly useless DB connector. I don't actually use the REST
# interface in anger anymore, so it has lacked attention.
#
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt
class RTDB

    attr_reader :summary

    Translate={0=>:checked_out,
        1=>:success,
        2=>:fail,
        3=>:crash,
        :checked_out=>0,
        :success=>1,
        :fail=>2,
        :crash=>3}

    def initialize(dbpath)
        begin
            @db=Sequel.connect("sqlite://#{dbpath}")
        rescue
            raise RuntimeError, "RTDB: Couldn't connect to @db: #{$!}"
        end

        @db.create_table :crash_results do
            primary_key :id
            column :result, :integer
            column :timestamp, :datetime
        end unless @db.table_exists? :crash_results

        @db.create_table :crash_files do
            primary_key :id
            column :crashdetail_path, :string
            column :crashfile_path, :string
            column :crash_id, :integer
        end unless @db.table_exists? :crash_files

        @summary={}
        @summary[:current_count]=@db[:crash_results].count
        @grouped=@db[:crash_results].group_and_count(:result)
        [:success,:crash,:fail].each {|sym|
            @summary[sym]=Integer(@grouped[:result=>Translate[sym]][:count]) rescue 0
        }
    end

    def count_results
        @db[:crash_results].filter('result > 0').count 
    end

    def result_summary
        @old_count||=@summary[:current_count]
        @old_time||=Time.now
        @summary[:speed]="%.2f" % ((@summary[:current_count]-@old_count) / (Time.now - @old_time).to_f)
        @old_count=@summary[:current_count]
        @old_time=Time.now
        @summary
    end

    def results_outstanding
        @db[:crash_results].filter(:result=>Translate[:checked_out]).count
    end

    def result_for_id(id)
        @db[:crash_results][:id=>id]  # A hash
    end

    def crashfile_for_id(id)
        @db[:crash_files][:crash_id=>id][:crashfile_path] # Path as string
    end

    def crashdetail_for_id(id)
        @db[:crash_files][:crash_id=>id][:crashdetail_path] # Path as string
    end

    def insert_result(id, result_sym, crashdetail_path=nil, crashfile_path=nil)
        unless Translate[@db[:crash_results][:id=>id][:result]]==:checked_out
            raise RuntimeError, "RTDB: Result #{id} not checked out."
        else
            begin
                @db[:crash_results][:id=>id]={:result=>Translate[result_sym],:timestamp=>Time.now}
                @summary[:current_count]+=1
                @summary[result_sym]+=1
            rescue
                sleep 1
                @db[:crash_results][:id=>id]={:result=>Translate[result_sym],:timestamp=>Time.now}
                @summary[:current_count]+=1
                @summary[result_sym]+=1
            end
            if result_sym==:crash
                unless crashdetail_path && crashfile_path
                    raise RuntimeError, "RTDB: crash, but no details!"
                else
                    unless File.exists?(crashdetail_path) && File.exists?(crashfile_path)
                        raise RuntimeError, "RTDB: Invalid path"
                    else
                        begin
                            @db[:crash_files].insert(:crashdetail_path=>crashdetail_path,:crashfile_path=>crashfile_path,:crash_id=>id)
                        rescue
                            sleep 1
                            @db[:crash_files].insert(:crashdetail_path=>crashdetail_path,:crashfile_path=>crashfile_path,:crash_id=>id)
                        end
                    end
                end
            end
        end
    end

    def check_out
        @db[:crash_results].insert(:result=>0,:timestamp=>Time.now)  # returns the primary key
    end
end
