@echo off

@echo off
mode con: cols=100 lines=50
:Sangfor
title  Logparser��־�������߸�����  
cls                            
echo.                   
echo.                      
echo ---------------------------  Logparser��־�������߸�����    -------------------------------                                            

echo    * ע�⣺�˽ű��轫C:\Windows\System32\winevt\Logs���Ƶ�C�̸�Ŀ¼��ʹ�ã��ļ���logs����Сд�����У�
echo    * ������ϵͳ����Ա������У����������ֺ�û�е�����������ǰ������û�ж�Ӧ��־
echo    * ��һ�β�ѯ��ɺ󣬰��س��ɽ��еڶ��β�ѯ
echo.    
echo    1: �鿴���е�½�ɹ���־
echo.
echo    2: �鿴����IP��½ʧ����־
echo. 
echo    3: �鿴RDP��½�ɹ���־����ǰ������˭��½����
echo.
echo    4: �鿴RDP���Ӽ�¼����ǰ����������Щ������
echo.
echo    5: �û�������¼
echo.
echo    6: �û�Ȩ���޸ļ�¼���û��Ƿ�����ӹ����飩
echo.
echo    7: �����޸ļ�¼��Ŀǰ��֧�ֲ鿴�����˺��޸ļ�¼��
echo.
echo    8: SQLServer���ݿ��½ʧ�ܼ�¼
echo.
echo    9: SQLServer���ݿ������޸ģ���Ҫ�鿴xp_cmdshell������¼��
echo.
echo.  10: ���յ�¼ʧ���û��Ĵ�����������  
echo.
echo   11: ��ѯָ��IP�ĵ�½ʧ�ܵ� �û�������½ʱ�䡢��ʽ����½IP�����ö˿�   
echo.
echo   12: ��ѯָ��IP�ĵ�½�ɹ��� �û�������½ʱ�䡢��ʽ����½IP�����ö˿�  
echo.
echo   13: �鿴����װ��¼����Ҫ�鿴todesk�����տ���processhacker�ȳ���װ��ms17_010���������ŷ���ȼ�¼��
echo.
echo   14: Powershellִ�м�¼
echo.
echo   15: ��½���Ͳ鿴��
echo.
echo   16: ��½ʧ��ԭ���                                      
echo -------------------------------------------------------------------------------------------
set start=
set /p start=    ������Ҫ�鿴�Ķ�Ӧ���ֺ󰴻س���: 
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
set /p IP=    ��������Ҫ������IP 
SET IP=%IP:"=%
start /b %~dp0\LogParser.exe -i:EVT  -o:DATAGRID "SELECT TimeGenerated,EXTRACT_TOKEN(Strings,5,'|') AS USERNAME,EXTRACT_TOKEN(Strings,10,'|') AS LOGON_TYPE,EXTRACT_TOKEN(Strings,19,'|') AS Client_IP,EXTRACT_TOKEN(Strings,6,'|') AS Domain_name, EXTRACT_TOKEN(Message, 0, ' ') AS Message FROM C:\logs\security.evtx WHERE EventID=4625 and EXTRACT_TOKEN(Strings,19,'|')='%IP%'
pause
goto end

:SEARCH_IP_SUCCESED
set IP = 
set /p IP=    ��������Ҫ������IP 
SET IP=%IP:"=%
start /b %~dp0\LogParser.exe -i:EVT "SELECT TimeGenerated AS Date, EXTRACT_TOKEN(Strings, 5, '|') as Username, EXTRACT_TOKEN(Strings, 6, '|') as Domain, EXTRACT_TOKEN(Strings, 8, '|') as LogonType,EXTRACT_TOKEN(strings, 9, '|') AS AuthPackage, EXTRACT_TOKEN(Strings, 11, '|') AS Workstation, EXTRACT_TOKEN(Strings, 17, '|') AS ProcessName, EXTRACT_TOKEN(Strings, 18, '|') AS SourceIP, EXTRACT_TOKEN(Message, 0, ' ') AS Message FROM  C:\logs\security.evtx WHERE EventID = 4624 AND Username NOT IN ('SYSTEM'; 'ANONYMOUS LOGON'; 'LOCAL SERVICE'; 'NETWORK SERVICE') AND Domain NOT IN ('NT AUTHORITY') AND LogonType = '10' AND EXTRACT_TOKEN(Strings,19,'|')='%IP%' " -o:DATAGRID
pause
goto end

:SERVER
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated as ʱ��, EventID, EXTRACT_TOKEN(Strings, 0, '|') as ��������, EXTRACT_TOKEN(Strings, 1, '|') as ӳ��·��, EXTRACT_TOKEN(Strings, 2, '|') as ��������,  EXTRACT_TOKEN(Strings, 3, '|') as ������������, EXTRACT_TOKEN(Strings, 4, '|') as �����˻�, ComputerName as ������� FROM C:\logs\System.evtx where EventID IN (7045) ORDER BY timegenerated DESC"
pause
goto end

:RDP_Connect
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated, EventID, EXTRACT_TOKEN(Strings, 1, '|') as SeverAddress, ComputerName FROM C:\logs\Microsoft-Windows-TerminalServices-RDPClient%%4Operational.evtx where EventID IN (1102;1024) ORDER BY timegenerated DESC"
pause
goto end

:Powershell
start /b %~dp0\LogParser.exe -i:EVT -o:DATAGRID  "SELECT TimeGenerated, EventID, EXTRACT_TOKEN(Strings, 7, '=') as ����, SourceName, ComputerName FROM  'C:\logs\Windows PowerShell.evtx' where EventID IN (400) ORDER BY timegenerated DESC"
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
echo -------------------------  ��½����  -------------------------
echo    Logon type 2 Interactive
echo         * ���ؽ�����¼������ĵ�¼��ʽ��
echo    Logon type 3 
echo         * Network �����¼ - ������Ƿ������繲���ļ��л��ӡ����IIS����֤Ҳ��Type 3
echo    Logon type 4 
echo         * Batch �ƻ�����
echo    Logon Type 5 
echo         * Service ����  ĳЩ��������һ�����ʺ������еģ�����Failure����������ǹ���Ա���������ʺ����룬������������Service�е��ʺ����롣
echo    Logon Type 7 
echo         * Unlock �����Ļ����   �ܶ๫˾���������İ�ȫ���ã����û��뿪��Ļһ��ʱ�����������������������Ļ���⿪��Ļ������Ҫ�����û��������롣��ʱ��������־���;���Type 7
echo    Logon Type 8 
echo         * NetworkCleartext �������ĵ�¼ -- ͨ��������IIS �� ASP��¼�����Ƽ�
echo    Logon Type 9 
echo         * NewCredentials ����ݵ�¼ -- ͨ��������RunAS��ʽ����ĳ����ʱ�ĵ�¼��֤��
echo    Logon Type 10 
echo         * RemoteInteractive Զ�̵�¼ -- ����Terminal service����RDP��ʽ������Windows 2000��û��Type10�ģ���Type 2��WindowsXP/2003����Type 10
echo    Logon Type 11 
echo         * CachedInteractive �����¼
echo
pause
goto end

:HELP
echo -------------------------  ��½ʧ��ԭ��  -------------------------
echo.
echo ��λ����״̬:ʮ�����ƴ�����͵�¼ʧ�ܵ�ԭ����ʱ��״̬��,��ʱ���ǡ�
echo ��λ����״̬��  ����(�����ʧ�ܵ�ԭ��:�����)
echo 
echo 0 xc0000064  �û���������
echo 
echo 0 xc000006a  �û�������ȷ��,�������Ǵ����
echo 
echo 0 xc0000234  �û���ǰ����
echo 
echo 0 xc0000072  �ʻ�Ŀǰ����
echo 
echo 0 xc000006f  �û���ͼ��¼������ܻ�ʱ������
echo 
echo 0 xc0000070  ����վ������
echo 
echo 0 xc0000193  �ʺŹ���
echo 
echo 0 xc0000071  ���ڵ�����
echo 
echo 0 xc0000133  ʱ��֮���ֱ������������̫��ͬ��
echo 
echo 0 xc0000224  ���´ε�¼�û���Ҫ��������
echo 
echo 0 xc0000225  ��Ȼһ��ȱ����Windows�Ͳ���һ������
echo 
echo 0 xc000015b  û�б�������û������¼����(������¼��ȷ��)����̨����
echo 
echo 0 xc000006d  �ƺ�������ϵͳ����Ͳ���ȫ��
pause

goto end


:end
echo
goto Sangfor