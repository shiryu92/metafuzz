require File.dirname(__FILE__) + '/../core/connector'
require File.dirname(__FILE__) + '/conn_office'
require File.dirname(__FILE__) + '/conn_cdb'

class Word

    def initialize
        begin
            5.times do
                begin
                    @word_conn=Connector.new(CONN_OFFICE, 'word')
                    break
                rescue
                    sleep(1)
                    next
                end
            end
            @current_pid=@word_conn.pid
        rescue
            raise RuntimeError, "Couldn't establish connection to app. #{$!}"
        end
        # Attach debugger
        @debugger=Connector.new(CONN_CDB,"-xi ld -p #{@current_pid}")
        @debugger.puts "!load winext\\msec.dll"
        @debugger.puts ".sympath c:\\localsymbols"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy\" av"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy\" sbo"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy\" ii"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy\" gp"
        @debugger.puts "sxi e0000001"
        @debugger.puts "sxi e0000002"
        @debugger.puts "g"
    end

    def deliver( filename, extra_data="", repair=true )
        status='error'
        crash_details="#{extra_data}\n"
        begin
            warn "Filename: #{filename}"
            @word_conn.blocking_write( filename, repair )
            # As soon as the deliver method doesn't raise an exception, we lose interest.
            status='success'
        rescue Exception=>e
            # check for crashes
            crash_details << e.inspect
            crash_details << e.backtrace.join("\n")
            crash_details << "\n---DEBUGGER OUTPUT---\n"
            sleep(0.1) #shitty race, sometimes
            if (crash_details << @debugger.dq_all.join) =~ /frobozz/
                until crash_details=~/xyzzy/
                    crash_details << @debugger.dq_all.join
                end
                status='crash'
                @debugger.puts ".dump /m #{filename}.dmp"
                @debugger.puts q
            else
                status='fail'
            end
        end
        [status,crash_details]
    end

    def destroy
        @word_conn.close rescue nil
        @debugger.close rescue nil
    end

    def method_missing( meth, *args )
        warn "MM: #{meth}"
        @word_conn.send( meth, *args )
    end

end

