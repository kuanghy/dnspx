@echo off

sc create DNSPX binPath= "D:\Applications\dnspx\dnspx.exe --service" start= delayed-auto displayname= "DNSPX Service"

pause
exit
