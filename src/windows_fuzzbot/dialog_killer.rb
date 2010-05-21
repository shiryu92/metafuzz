require 'Win32API'

# More nasty code. This uses window messages to try and kill off dialog boxes.
# It doesn't care what they are, it just tries to get rid of them.
#
# This is the second of the two files that run alongside the fuzzclient.
# ---
# This file is part of the Metafuzz fuzzing framework.
# Author: Ben Nagy
# Copyright: Copyright (c) Ben Nagy, 2006-2009.
# License: All components of this framework are licensed under the Common Public License 1.0. 
# http://www.opensource.org/licenses/cpl1.0.txt

BMCLICK=0x00F5
WM_DESTROY=0x0010
WM_COMMAND=0x111
IDOK=1
IDCANCEL=2
IDNO=7
IDCLOSE=8
GW_ENABLEDPOPUP=0x0006

FindWindow=Win32API.new("user32.dll", "FindWindow", 'PP','N')
GetWindow=Win32API.new("user32.dll", "GetWindow", 'LI','I')
PostMessage=Win32API.new("user32.dll", "PostMessage", 'LILL','I')

def kill_dialog_boxes
    word_hwnd=FindWindow.call("OpusApp",0)
    # Get any descendant windows which are enabled - alerts, dialog boxes etc
    child_hwnd=GetWindow.call(word_hwnd, GW_ENABLEDPOPUP)
    unless child_hwnd==0
        PostMessage.call(child_hwnd,WM_COMMAND,IDCANCEL,0)
        PostMessage.call(child_hwnd,WM_COMMAND,IDNO,0)
        PostMessage.call(child_hwnd,WM_COMMAND,IDCLOSE,0)
        PostMessage.call(child_hwnd,WM_COMMAND,IDOK,0)
        PostMessage.call(child_hwnd,WM_DESTROY,0,0)
      end
      # The script changes the caption, so this should only detect toplevel dialog boxes
      # that pop up during open before the main Word window.
      toplevel_box=FindWindow.call(0, "Microsoft Office Word")
      unless toplevel_box==0
        PostMessage.call(toplevel_box,WM_COMMAND,IDCANCEL,0)
        PostMessage.call(toplevel_box,WM_COMMAND,IDNO,0)
        PostMessage.call(toplevel_box,WM_COMMAND,IDCLOSE,0)
        PostMessage.call(toplevel_box,WM_COMMAND,IDOK,0)
      end
end

loop do
    begin
        kill_dialog_boxes
    rescue 
        puts "Wordslayer: DK: #{$!}"
    end
    sleep(0.5)
end
