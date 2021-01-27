@echo off

sc create dnspx binPath= "D:\dnspx\dnspx.exe --config D:\dnspx\config" start= delayed-auto displayname= dnspx

pause
exit
