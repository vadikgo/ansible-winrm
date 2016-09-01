**** Настройка Windows для подключения по winrm без прав администратора

Для выполнения команд Remote Power Shell на Windows 2008 и выше необходимо настроить winrm. Данные настройки протестированы для запуска команд под управлением ansible. Код использовавшийся для тестирования находится здесь:

[https://github.com/vadikgo/ansible-winrm.git]

Пошаговое руководство

1. Установить .Net 4.5 (NDP452-KB2901907-x86-x64-AllOS-ENU.exe) и Power Shell 4.0. Для Windows 2008 R2 можно скачать: Windows6.1-KB2819745-x64-MultiPkg.msu. Для Windows 2012 идет в составе ОС. Можно выполнить установку скриптом https://github.com/vadikgo/ansible-winrm/blob/master/files/install_ps4.cmd. Узнать версию PowerShell командой PowerShell: Get-Host

2. Сконфигурировать winrm. Для этого необходимо выполнить PowerShell скрипт: https://github.com/vadikgo/ansible-winrm/blob/master/files/ConfigureRemotingForAnsible.ps1
Для отображения процесса, можно перед запуском задать в консоли PowerShell переменную `$VerbosePreference = "Continue"`.

3. Создать локальную группу для доступа. Под Windows 2012 данные настройки уже выполнены и доступ предоставляется участникам локальной группы Remote Management Users. Можно использовать скрипт https://github.com/vadikgo/ansible-winrm/blob/master/files/create-group.ps1

4. Предоставить группе необходимый доступ. Под Windows 2012 этот этап можно пропустить.

a. Посмотреть текущие права можно командой Power Shell: `get-pssessionconfiguration | fl Name,Permission`

b. Задать доступ командами, добавив права Execute(invoke) группе из шага 3 с использованием скрипта https://github.com/vadikgo/ansible-winrm/blob/master/files/Add-PoShEndpointAccess.ps1 и https://github.com/vadikgo/ansible-winrm/blob/master/files/grant-winrm-remote.ps1

```
               Add-PoShEndpointAccess.ps1 -SamAccountName " " -EndpointName
               Microsoft.PowerShell
               Add-PoShEndpointAccess.ps1 -SamAccountName " " -EndpointName
               Microsoft.PowerShell32
               Add-PoShEndpointAccess.ps1 -SamAccountName " " -EndpointName
               Microsoft.PowerShell.Workflow
               Get-Service -Name WinRM | Restart-Service
               grant-winrm-remote.ps1 " "
```

эти команды реализуют настройку аналогичную выполняемой через графический интерфейс:
Все команды пунктов 2-4 можно выполнить одним скриптом https://github.com/vadikgo/ansible-winrm/blob/master/files/set-winrm-main.ps1
Скачать скрипт в текущий каталог сервера командой PowerShell:

```
Invoke-WebRequest -uri "http://stash.ca.sbrf.ru/projects/OASIBUR/repos/ansible-winrm/browse/files/setup-winrm.ps1?raw" -OutFile .\setup-winrm.ps1
create-group.ps1 "Remote Management Users"
```  

```
winrm configSDDL default
Set-PSSessionConfiguration -name microsoft.powershell
-showSecurityDescriptorUI -force
Set-PSSessionConfiguration -name microsoft.powershell32
-showSecurityDescriptorUI -force
Set-PSSessionConfiguration -name microsoft.powershell.workflow
-showSecurityDescriptorUI -force
```

c. Добавить доступ к удаленному чтению WMI (https://github.com/vadikgo/ansible-winrm/blob/master/files/Set-WmiNamespaceSecurity.ps1):
            `Set-WmiNamespaceSecurity.ps1 root/cimv2 add _ Enable,RemoteAccess`
5. Проверить доступность Windows по WinRM можно командой PowerShell c рабочей станции Windows
       `Enter-PSSession _`
или с ansible control host
       `ansible all -m win_ping -v`
Проверить доступ к wmi с ansible control host
       `ansible all -m setup`
      После предоставление прав на чтение WMI необходимо перезагрузить Windows.

Использовались статьи
* https://4sysops.com/archives/powershell-remoting-without-administrator-rights/
* http://serverfault.com/questions/590515/how-to-allow-access-to-winrs-for-non-admin-user
* https://www.sevecek.com/Lists/Posts/Post.aspx?ID=280
