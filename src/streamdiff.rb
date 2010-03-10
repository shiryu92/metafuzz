require 'diff/lcs'
require 'ole/storage'
require 'generators'

# A module for diffing OLE2 files, by first reassembling the internal document
# streams and diffing on a per-stream basis. The most notable limitation is that
# it doesn't support length mismatches, which is purely based on expedience.
module StreamDiff

    # The diff/lcs gem creates a diff structure where multi-byte differences are broken
    # down into individual entries. This function 'coalesces' those differences, and
    # returns a result hash which also contains some structures that are used in the
    # crash reducer.
    def coalesce_diffs( diff_hsh )
        results=[]
        diff_hsh.each {|cc|
            raise RuntimeError, "oldpos not newpos, dunno what to do" unless cc.old_position==cc.new_position
            raise RuntimeError, "Length mismatch, can't handle." unless cc.old_element.length==cc.new_element.length
            if results.last and cc.old_position==results.last[0]+results.last[1][0].length
                # Contiguous, coalesce with the last difference.
                results.last[1][0] << cc.old_element
                results.last[1][1] << cc.new_element
            else
                #  new difference
                results << [cc.old_position,[cc.old_element,cc.new_element]]
            end
        }
        result_hash={}
        # One of these hashes per stream / dirent, hash of offset -> difference detail structure.
        results.each {|ary| 
            offset=ary[0]
            result_hash[offset]={}
            result_hash[offset][:old_elem]=ary[1][0]
            result_hash[offset][:new_elem]=ary[1][1]
            # Binary versions. These strings will be modified by the reducer.
            result_hash[offset][:old_binary]=result_hash[ary[0]][:old_elem].unpack('B*').first
            result_hash[offset][:new_binary]=result_hash[ary[0]][:new_elem].unpack('B*').first
            # As we gradually revert, the replacement will be left_reverted + new_binary +
            # right_reverted.
            result_hash[offset][:left_reverted]=""
            result_hash[offset][:right_reverted]=""
            # The binary masks will show which bits of the final item "matter". If we can
            # revert a bit to the old value (which may be unchanged) and the crash is the
            # same then the bit in question doesn't matter.
            result_hash[offset][:left_mask]=""
            result_hash[offset][:right_mask]=""
            # Initially, we set all bits to 'matter'
            result_hash[offset][:mid_mask]="1"*result_hash[ary[0]][:old_binary].length
        }
        # In summary:
        # left_reverted and right_reverted grow, new binary shrinks
        # left_reverted+new_binary+right_reverted will be the next test
        # left_mask and right_mask grow, mid_mask is always "111..11" and shrinks
        result_hash
    end

    def generate_diffs(old_fname, new_fname)
        begin
            old_ole=Ole::Storage.open(old_fname)
            new_ole=Ole::Storage.open(new_fname)
            old_streams=Hash[*(old_ole.dirents.map {|dirent| 
                next if dirent.dir?;[dirent.name,dirent.read]
            }).compact.flatten]
            new_streams=Hash[*(new_ole.dirents.map {|dirent| 
                next if dirent.dir?;[dirent.name,dirent.read]
            }).compact.flatten]
        rescue
            raise RuntimeError, "Couldn't open files as OLE2: #{$!}"
        ensure 
            old_ole.close
            new_ole.close
        end
        coalesced={}
        old_streams.each {|dirent,contents|
            # The compobj table changes virtually every time an OLE2 file is unpacked and repacked.
            # So don't check it for differences.
            next if dirent=~/compobj/i
            next if new_streams[dirent]==contents
            coalesced[dirent]=coalesce_diffs(Diff::LCS.sdiff(contents, new_streams[dirent]).select {|cc| 
                cc.action=='!' # Only changes, remember that we don't support different lengths yet
            })
        }
        # Hash of stream -> differences, where differences is a hash of offset -> difference hash
        coalesced
    end

    # Apply all the diffs to the template file.
    def diffs_to_raw( template, diffs )
        raw=StringIO.new(template.clone)
        Ole::Storage.open(raw) {|ole|
            diffs.each {|stream, diff_hsh|
                # Read in this stream
                stream_contents=ole.file.open(stream, "rb") {|f| f.read}
                # make all the changes
                diff_hsh.each {|offset, chunk|
                    replacement=chunk[:left_reverted]+chunk[:new_binary]+chunk[:right_reverted]
                    stream_contents[offset,replacement.length]=replacement
                }
                # write the stream back to the ole file
                ole.file.open(stream,"wb+") {|f| f.write stream_contents}
            }
        }
        raw.rewind
        raw.read
    end

    # Return how many bits are marked as 'to enumerate' - in other words
    # the new value of the bit changes the crash when the test is sent.
    def bits_to_enumerate( coalesced_hsh )
        # I bet this is slow as hell...
        coalesced_hsh.values.inject(0) {|s,diff_hsh|
            s+=diff_hsh.values.inject(0) {|s, chunk_hsh|
                s+=chunk_hsh[:left_mask].scan('1').length
                s+=chunk_hsh[:right_mask].scan('1').length
                s+=chunk_hsh[:mid_mask].length
            }
        }
    end
    module_function :bits_to_enumerate, :generate_diffs, :coalesce_diffs
end

if __FILE__==$0
    old,new=ARGV
    coalesced=StreamDiff::generate_diffs(old,new)
    puts "Total bits changed is #{StreamDiff::bits_to_enumerate(coalesced)}"
    def the_same_crash?( coalesced_hsh )
        return rand < 0.7
    end
    reducer=Fiber.new do |coalesced|
        coalesced.each {|stream, diff_hsh|
            diff_hsh.each {|offset,chunk|
                if chunk[:new_binary].length > 8
                    puts "Trying to reduce #{chunk}..."
                    # left_reverted and right_reverted will hold fragments of
                    # the old_binary, new_binary will get modified by slice!
                    # until it contains just the unreverted bits. At each step, to
                    # send, we can just join left_reverted, new_binary, right_reverted.
                    # At the same time, we build the mask which will be used to create a
                    # generator that enumerates all the bits that matter and masks out
                    # the ones that don't
                    loop do
                        break if StreamDiff::bits_to_enumerate(coalesced) < 19
                        break if chunk[:old_binary].empty?
                        chunk[:left_reverted] << chunk[:old_binary].slice!(0,1)
                        chunk[:new_binary].slice!(0,1)
                        chunk[:mid_mask].slice!(0,1)
                        # We yield here, so the test can be sent. When that code
                        # resumes this fiber, it needs to resume with a boolean.
                        if (Fiber.yield coalesced)
                            # This bit didn't change the crash, it doesn't matter.
                            chunk[:left_mask] << "0"
                        else
                            # This bit matters
                            chunk[:left_mask] << "1"
                        end
                        break if StreamDiff::bits_to_enumerate(coalesced) < 19
                        break if chunk[:old_binary].empty?
                        chunk[:right_reverted]=chunk[:old_binary].slice!(-1,1)+chunk[:right_reverted]
                        chunk[:new_binary].slice!(-1,1)
                        chunk[:mid_mask].slice!(-1,1)
                        if (Fiber.yield coalesced)
                            chunk[:right_mask]="0" << chunk[:right_mask]
                        else
                            chunk[:right_mask]="1" << chunk[:right_mask]
                        end
                    end
                end
                break if StreamDiff::bits_to_enumerate(coalesced) < 19
            }
        }
        raise StopIteration
    end
    begin
        # Get the first test before we start the delivery loop
        test=reducer.resume coalesced
        loop do
            #deliver test and get result
            result=(rand < 0.7)
            coalesced=reducer.resume result
        end
    rescue StopIteration
    end
    puts "Total bits left to change is #{StreamDiff::bits_to_enumerate(coalesced)}"
    coalesced.each {|stream, diff_hsh|
        diff_hsh.each {|offset,chunk| 
            mask=chunk[:left_mask]+chunk[:mid_mask]+chunk[:right_mask]
            # Split the mask so all the contiguous sections of '1' are together
            # will look like ["000","1","00","1111", ....]
            ary=mask.split(/(1+)/).reject {|s| s.empty?}
            old_binary=chunk[:old_elem].unpack('B*').first
            with_gens=[]
            ary.each {|elem|
                if elem =~ /0/
                    # Element that should not be changed because it
                    # doesn't affect the crash. Take this much of the
                    # string from the old_binary.
                    with_gens << [old_binary.slice!(0,elem.length)]
                else
                    # Element that needs to be enumerated. Create a generator
                    # to enumerate this many bits and add it to the array.
                    with_gens << Generators::EnumerateBits.new(elem.length)
                    old_binary.slice!(0,elem.length)
                end
            }
            puts "Old binary should be 0: #{old_binary.length==0}"
            puts "#{chunk[:old_elem].unpack('B*').first} fiddle with #{with_gens}"
            # This is now the generator for this chunk. It will enumerate the
            # full set product of all the elements that need to be enumerated
            # while leaving the 'don't matter' parts of the string alone.
            chunk[:generator]=Generators::Cartesian.new *with_gens
        }
    }
    gens=[]
    # Now go through all the streams and combine the generators for all chunks
    # in the file that changed.
    coalesced.each {|stream, diff_hsh|
        diff_hsh.each {|offset,chunk| 
            gens << [stream]; gens << [offset]; gens << chunk[:generator]
        }
    }
    final=Generators::Cartesian.new *gens
    count=0
    until final.finished?
        count+=1
        final.next
    end
    puts "#{count} tests."
end
