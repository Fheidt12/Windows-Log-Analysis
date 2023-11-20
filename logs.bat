@echo off

@echo off
mode con: cols=100 lines=50
:Sangfor
title  Logparser日志分析工具改良版  
cls                            
echo.                   
echo.                      
echo ---------------------------  Logparser日志分析工具改良版    -------------------------------                                            

echo    * 注意：此脚本需将C:\Windows\System32\winevt\Logs复制到C盘跟目录下使用，文件名logs（大小写不敏感）
echo    * 必须以系统管理员身份运行，若输入数字后没有弹出表格则代表当前服务器没有对应日志
echo    * 第一次查询完成后，按回车可进行第二次查询
echo.    
echo    1: 查看所有登陆成功日志
echo.
echo    2: 查看所有IP登陆失败日志
echo. 
echo    3: 查看RDP登陆成功日志（当前主机被谁登陆过）
echo.
echo    4: 查看RDP连接记录（当前主机连过哪些机器）
echo.
echo    5: 用户创建记录
echo.
echo    6: 用户权限修改记录（用户是否有添加管理组）
echo.
echo    7: 密码修改记录（目前不支持查看机器账号修改记录）
echo.
echo    8: SQLServer数据库登陆失败记录
echo.
echo    9: SQLServer数据库配置修改（主要查看xp_cmdshell开启记录）
echo.
echo.  10: 按照登录失败用户的次数进行排序  
echo.
echo   11: 查询指定IP的登陆失败的 用户名、登陆时间、方式、登陆IP、所用端口   
echo.
echo   12: 查询指定IP的登陆成功的 用户名、登陆时间、方式、登陆IP、所用端口  
echo.
echo   13: 查看程序安装记录（主要查看todesk、向日葵、processhacker等程序安装、ms17_010攻击、后门服务等记录）
echo.
echo   14: Powershell执行记录
echo.
echo   15: 登陆类型查看表
echo.
echo   16: 登陆失败原因表                                      
echo -------------------------------------------------------------------------------------------
set start=
set /p start=    输入需要查看的对应数字后按回车键: 
if "%start%"=="1" goto ALL
if "%start%"=="2" goto FAILED_BY_IP
if "%start%"=="3" goto RDP_SUCCESS
if "%start%"=="4" goto RDP_Connect
if "%start%"=="5" goto Create_user
if "%start%"=="6" goto Change_group
if "%start%"=="7" goto Change_password
if "%start%"=="8" goto SQLServer_login
if "%start%"=="9" goto SQLServer_config
if "%start%"=="10" goto FAILED
if "%start%"=="11" goto SEARCH_IP_FAILED
if "%start%"=="12" goto SEARCH_IP_SUCCESED
if "%start%"=="13" goto SERVER
if "%start%"=="14" goto Powershell
if "%start%"=="15" goto login_type
if "%start%"=="16" goto HELP

goto Sangfor


:ALL
echo %~dp0
start  /b %~dp0\LogParser.exe -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP ,EventID, EXTRACT_TOKEN(Message, 0, ' ') AS Message,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName FROM C:\logs\security.evtx WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') ORDER BY timegenerated DESC" -o:DATAGRID
pause
goto end

:RDP_SUCCESS
start /b %~dp0\LogParser.exe  -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP, EXTRACT_TOKEN(Message, 0, ' ') AS Message FROM C:\logs\security.evtx WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND LogonType = '10' ORDER BY timegenerated DESC" -o:DATAGRID
pause
goto end

:FAILED
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID "SELECT TimeGenerated,EXTRACT_TOKEN(Strings,5,'|') AS USERNAME,EXTRACT_TOKEN(Strings,10,'|') AS LOGON_TYPE,EXTRACT_TOKEN(Strings,19,'|') AS Client_IP,EXTRACT_TOKEN(Strings,6,'|') AS Domain_name, EXTRACT_TOKEN(Message, 0, ' ') AS Message FROM C:\logs\security.evtx WHERE EventID=4625  ORDER BY timegenerated DESC"
pause
goto end

:FAILED_BY_IP
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID "SELECT EXTRACT_TOKEN(Strings,5,'|') AS USERNAME,count(EXTRACT_TOKEN(Strings,5,'|')) AS times ,EXTRACT_TOKEN(Strings,10,'|') AS LOGON_TYPE,EXTRACT_TOKEN(Strings,19,'|') AS Client_IP,EXTRACT_TOKEN(Strings,6,'|') AS Domain_name FROM C:\logs\security.evtx WHERE EventID=4625 GROUP BY Strings
pause
goto end

:SEARCH_IP_FAILED
set IP = 
set /p IP=    请输入需要搜索的IP 
SET IP=%IP:"=%
start /b %~dp0\LogParser.exe -i:EVT  -o:DATAGRID "SELECT TimeGenerated,EXTRACT_TOKEN(Strings,5,'|') AS USERNAME,EXTRACT_TOKEN(Strings,10,'|') AS LOGON_TYPE,EXTRACT_TOKEN(Strings,19,'|') AS Client_IP,EXTRACT_TOKEN(Strings,6,'|') AS Domain_name, EXTRACT_TOKEN(Message, 0, ' ') AS Message FROM C:\logs\security.evtx WHERE EventID=4625 and EXTRACT_TOKEN(Strings,19,'|')='%IP%'
pause
goto end

:SEARCH_IP_SUCCESED
set IP = 
set /p IP=    请输入需要搜索的IP 
SET IP=%IP:"=%
start /b %~dp0\LogParser.exe -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP, EXTRACT_TOKEN(Message, 0, ' ') AS Message FROM  C:\logs\security.evtx WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND LogonType = '10' AND EXTRACT_TOKEN(Strings,19,'|')='%IP%' " -o:DATAGRID
pause
goto end

:SERVER
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated as 时间, EventID, EXTRACT_TOKEN(Strings, 0, '|') as 服务名称, EXTRACT_TOKEN(Strings, 1, '|') as 映像路径, EXTRACT_TOKEN(Strings, 2, '|') as 服务类型,  EXTRACT_TOKEN(Strings, 3, '|') as 服务启动类型, EXTRACT_TOKEN(Strings, 4, '|') as 服务账户, ComputerName as 计算机名 FROM C:\logs\System.evtx where EventID IN (7045) ORDER BY timegenerated DESC"
pause
goto end

:RDP_Connect
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated, EventID, EXTRACT_TOKEN(Strings, 1, '|') as SeverAddress, ComputerName FROM C:\logs\Microsoft-Windows-TerminalServices-RDPClient%%4Operational.evtx where EventID IN (1102;1024) ORDER BY timegenerated DESC"
pause
goto end

:Powershell
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated, EventID, EXTRACT_TOKEN(Strings, 7, '=') as 命令, SourceName, ComputerName FROM  'C:\logs\Windows PowerShell.evtx' where EventID IN (400) ORDER BY timegenerated DESC"
pause
goto end

:SQLServer_config
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated, EventID, EXTRACT_TOKEN(Strings, 0, '1') as Config_option, EXTRACT_TOKEN(Strings, 1, '|') as Before_Status, EXTRACT_TOKEN(Strings, 2, '|') as Now_Status, SourceName, ComputerName FROM C:\logs\Application.evtx where EventID IN (15457) ORDER BY timegenerated DESC"
pause
goto end

:SQLServer_login
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated, EventID, EXTRACT_TOKEN(Strings, 0, '|') as Account, EXTRACT_TOKEN(Strings, 1, '|') as Reason, EXTRACT_TOKEN(Strings, 2, '|') as Client_IP, SourceName, ComputerName FROM C:\logs\Application.evtx where EventID IN (18456) ORDER BY timegenerated DESC"
pause
goto end

:Change_group
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated, EventID, EXTRACT_TOKEN(Strings, 6, '|') as user_name, EXTRACT_TOKEN(Strings, 2, '|') as target_group, EXTRACT_TOKEN(Message, 0, ' ') AS Message, ComputerName  FROM C:\logs\security.evtx WHERE EventID IN (4732)  ORDER BY timegenerated DESC"
pause
goto end

:Create_user
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated, EventID, EXTRACT_TOKEN(Strings, 0, '|') as Create_name, EXTRACT_TOKEN(Strings, 1, '|') as dst_domain, EXTRACT_TOKEN(Strings, 4, '|') as Src_name, EXTRACT_TOKEN(Strings, 5, '|') as src_domain, EXTRACT_TOKEN(Message, 0, ' ') AS Message, ComputerName FROM C:\logs\security.evtx WHERE EventID IN (4720)  ORDER BY timegenerated DESC"
pause
goto end

:Change_password
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated, EventID, EXTRACT_TOKEN(Strings, 4, '|') as use_name, EXTRACT_TOKEN(Strings, 5, '|') as use_domain, EXTRACT_TOKEN(Strings, 0, '|') as Target_name, EXTRACT_TOKEN(Strings, 1, '|') as Target_domain, EXTRACT_TOKEN(Message, 0, ' ') AS Message, ComputerName FROM C:\logs\security.evtx WHERE EventID IN (4724)  ORDER BY timegenerated DESC"
pause
goto end


:login_type
cls
echo -------------------------  登陆类型  -------------------------
echo    Logon type 2 Interactive
echo         * 本地交互登录。最常见的登录方式。
echo    Logon type 3 
echo         * Network 网络登录 - 最常见的是访问网络共享文件夹或打印机。IIS的认证也是Type 3
echo    Logon type 4 
echo         * Batch 计划任务
echo    Logon Type 5 
echo         * Service 服务  某些服务是用一个域帐号来运行的，出现Failure常见的情况是管理员更改了域帐号密码，但是忘记重设Service中的帐号密码。
echo    Logon Type 7 
echo         * Unlock 解除屏幕锁定   很多公司都有这样的安全设置：当用户离开屏幕一段时间后，屏保程序会锁定计算机屏幕。解开屏幕锁定需要键入用户名和密码。此时产生的日志类型就是Type 7
echo    Logon Type 8 
echo         * NetworkCleartext 网络明文登录 -- 通常发生在IIS 的 ASP登录。不推荐
echo    Logon Type 9 
echo         * NewCredentials 新身份登录 -- 通常发生在RunAS方式运行某程序时的登录验证。
echo    Logon Type 10 
echo         * RemoteInteractive 远程登录 -- 比如Terminal service或者RDP方式。但是Windows 2000是没有Type10的，用Type 2。WindowsXP/2003起有Type 10
echo    Logon Type 11 
echo         * CachedInteractive 缓存登录
echo
pause
goto end

:HELP
echo -------------------------  登陆失败原因  -------------------------
echo.
echo 地位和子状态:十六进制代码解释登录失败的原因。有时子状态是,有时不是。
echo 地位和子状态码  描述(不针对失败的原因:“检查)
echo 
echo 0 xc0000064  用户名不存在
echo 
echo 0 xc000006a  用户名是正确的,但密码是错误的
echo 
echo 0 xc0000234  用户当前锁定
echo 
echo 0 xc0000072  帐户目前禁用
echo 
echo 0 xc000006f  用户试图登录天的外周或时间限制
echo 
echo 0 xc0000070  工作站的限制
echo 
echo 0 xc0000193  帐号过期
echo 
echo 0 xc0000071  过期的密码
echo 
echo 0 xc0000133  时钟之间的直流和其他电脑太不同步
echo 
echo 0 xc0000224  在下次登录用户需要更改密码
echo 
echo 0 xc0000225  显然一个缺陷在Windows和不是一个风险
echo 
echo 0 xc000015b  没有被授予该用户请求登录类型(又名登录正确的)在这台机器
echo 
echo 0 xc000006d  似乎是由于系统问题和不安全。
pause

goto end


:end
echo
goto Sangfor