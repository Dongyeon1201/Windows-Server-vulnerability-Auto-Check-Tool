$secpasswd = ConvertTo-SecureString $args[1] -AsPlainText -Force

$mycreds = New-Object System.Management.Automation.PSCredential ($args[0], $secpasswd)

Invoke-Command -Credential $mycreds -ComputerName $args[2] -FilePath .\check\3_check_other_service.ps1
