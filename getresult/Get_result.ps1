$secpasswd = ConvertTo-SecureString $args[1] -AsPlainText -Force

$mycreds = New-Object System.Management.Automation.PSCredential ($args[0], $secpasswd)

$DestinationPath = $args[3]

$Date = $args[4]

$result = Invoke-Command -Credential $mycreds -ComputerName $args[2] -ScriptBlock {Get-Content ./check_result_more.txt}
$result | Set-Content -Encoding UTF8 ./check_result_more.txt

$result = Invoke-Command -Credential $mycreds -ComputerName $args[2] -ScriptBlock {Get-Content ./server_basic_info.txt}
$result | Set-Content -Encoding UTF8 ./server_basic_info.txt

Move-Item ./check_result_more.txt $DestinationPath
Move-Item ./server_basic_info.txt $DestinationPath

#remove result file in server
Invoke-Command -Credential $mycreds -ComputerName $args[2] -ScriptBlock {Remove-Item .\check_result_more.txt, .\server_basic_info.txt, .\user_rights}

powershell.exe -ExecutionPolicy Bypass -File .\getresult\write_document.ps1 $DestinationPath ($args[2]) ($Date)