Created by Ricardo Lemus with the help of AI and documentation available online.

Please note: If Security log / some commands fail, run PowerShell as Administrator and the command below in a different poweshell window.

"Set-ExecutionPolicy -Scope CurrentUser RemoteSigned"

This script will create a folder in the same directory the script is located in with a timestamp. It will collect baseline info such as OS info, local admins, Firewall status, Defender status, ports and failed logon attempts. It will then put all this info into a report in the same directory. A json file will be provided as well for the data to be structured. 


To run:

1. Right click "RunAudit.ps1" 
2. Let it run then hit "enter" when done

3. Text file will open automatically
