@echo off

sc create dnspx binPath= D:\dnspx\dnspx.exe start= delayed-auto displayname= dnspx

pause
exit
