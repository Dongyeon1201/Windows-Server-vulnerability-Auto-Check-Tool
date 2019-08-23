$secpasswd = ConvertTo-SecureString $args[1] -AsPlainText -Force

$mycreds = New-Object System.Management.Automation.PSCredential ($args[0], $secpasswd)

$command = "echo '" + $args[2] + "' > server_basic_info.txt"

$command = {$command}

Invoke-Command -Credential $mycreds -ComputerName $args[2] -ScriptBlock $command
Invoke-Command -Credential $mycreds -ComputerName $args[2] -FilePath  .\check\get_os_info.ps1

Invoke-Command -Credential $mycreds -ComputerName $args[2] -FilePath  .\check\1_check_Account.ps1
