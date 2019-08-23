$secpasswd = ConvertTo-SecureString $args[1] -AsPlainText -Force

$mycreds = New-Object System.Management.Automation.PSCredential ($args[0], $secpasswd)

# Session »Æ¿Œ
Enter-PSSession -Credential $mycreds -ComputerName $args[2] -EA Stop
Exit-PSSession