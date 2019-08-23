$flag = (Get-Command -Module Posh-SSH).Count # Check that the module is installable 

if($flag -eq 0)
{
    Install-Module -Name Posh-SSH -RequiredVersion 1.7.6 -Force # Install ssh Module 
}

# 비밀번호 설정
$sshPwd = ConvertTo-SecureString -String "kit2019" -AsPlainText -Force 
 
# 자격증명 생성
$sshCredential = new-object -typename System.Management.Automation.PSCredential -argumentlist "root", $sshPwd

# 대상 서버 접속
$SSHSession = New-SSHSession -ComputerName "192.168.0.32" -Credential $sshCredential -AcceptKey:$true
 
$sftpSession = New-SFTPSession -ComputerName "192.168.0.32" -Credential $sshCredential

Set-SFTPFile -SFTPSession $sftpSession  -LocalFile $args[0] -RemotePath "/root/PYH" -Overwrite

# 연결 끊기      
$sftpSession.Disconnect()
Remove-SSHSession -SSHSession $SSHSession
Remove-variable SSHSession
