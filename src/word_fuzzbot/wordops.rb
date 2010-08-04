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
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy;.kill;g\" av"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy;.kill;g\" sbo"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy;.kill;g\" ii"
        @debugger.puts "sxe -c \".echo frobozz;r;!exploitable -m;lm v;.echo xyzzy;.kill;g\" gp"
        @debugger.puts "sxi e0000001"
        @debugger.puts "sxi e0000002"
        @debugger.puts "g"
    end

    def deliver( filename, extra_data="" )
        status='error'
        crash_details="#{extra_data}\n--- DEBUGGER OUTPUT ---\n"
        begin
            @word_conn.deliver( filename, norepairdialog=false )
            # As soon as the deliver method doesn't raise an exception, we lose interest.
            status='success'
            @word_conn.close_documents
        rescue Exception=>e
            # check for crashes
            crash_details << e
            sleep(0.1) #shitty race, sometimes
            if (crash_details=@debugger.dq_all.join) =~ /frobozz/
                until crash_details=~/xyzzy/
                    crash_details << @debugger.dq_all.join
                end
                status='crash'
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
        @word_conn.send( meth, *args )
    end

end

