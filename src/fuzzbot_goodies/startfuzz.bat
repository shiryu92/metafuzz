=====================
rmdir /s /q c:\fuzzbot_code
ping -n 90 192.168.122.1
xcopy /d /y /s \\192.168.122.1\ramdisk\fuzzbot_code c:\fuzzbot_code\
copy /y c:\fuzzbot_code\startfuzz.bat c:\AUTOEXEC.BAT
c:\fuzzbot_code\compname /c BUGMINER-?8
rmdir /s /q r:\fuzzclient
mkdir r:\fuzzclient
C:\WinDDK\Debuggers\gflags /p /enable WINWORD.EXE /full
cd c:\fuzzbot_code\word_fuzzbot
start cmd /k ruby word_fuzzclient_new.rb
