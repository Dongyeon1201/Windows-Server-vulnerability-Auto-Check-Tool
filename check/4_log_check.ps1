function Test-Role 
{
  Param( [Security.Principal.WindowsBuiltinRole]$Role )

  $CurrentUser = [Security.Principal.WindowsPrincipal]([Security.Principal.WindowsIdentity]::GetCurrent())

  $CurrentUser.IsInRole($Role)
}

# 공백 / 줄바꿈이 존재하는 object형 결과값을 공백없는 String형 결과값으로 바꿔주는 함
function String([object]$string)
{
    $string_return = Out-String -InputObject $string
    $string_return = $string_return.Split(" ")[0]
    $string_return = $string_return.Split("`r")[2]
    $string_return = $string_return.Split("`n")[1]

    return $string_return
}

# 경로의 권한을 얻어온다.
function Get-Permissions($Path)
{
    (Get-Acl -Path $Path).Access | select 
    @{Label="identity"; Expression={$_.IdentityReference}}
}

# 레지스트리 키 이름, 타입, 값을 출력해준다.
function Get-RegistryValue
{
    param
    (
        [Parameter(Mandatory = $true)]
        $RegistryKey
    )

    $key = Get-Item -Path "Registry::$RegistryKey"
    $key.GetValueNames() |
    ForEach-Object {
        $name = $_
        $rv = 1 | Select-Object -Property Name, Type, Value
        $rv.Name = $name
        $rv.Type = $key.GetValueKind($name)
        $rv.Value = $key.GetValue($name)
        $rv
  
    }
}

# 입력된 경로의 레지스트리 키가 존재하는지 확인한다.
function Test-RegistryValue($regkey, $name) 
{
    try
    {
        $exists = Get-ItemProperty $regkey $name -ErrorAction SilentlyContinue
        if (($exists -eq $null) -or ($exists.Length -eq 0))
        {
            return $false
        }
        else
        {
            return $true
        }
    }
    catch
    {
        return $false
    }
}

#SID를 계정이름으로 변경해준다.
function Convert_SID_TO_USERNAME($SID)
{
    $objSID = New-Object System.Security.Principal.SecurityIdentifier($SID)
    $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
    return ($objUser.Value)
}

#################### FTP 사이트 이름과 경로는 자주 점검에 자주 사용되므로 미리 구해둔다. ####################

$FTP_Site_List = Get-IISSite | Where-Object {$_.Bindings -like "*ftp*"} | select-Object Name

$FTP_Site_Name_list=@()
$FTP_Site_Path_list=@()
$FTP_Site_Path_Full_Path_list=@()

foreach($name_item in $FTP_Site_List)
{
    $name_item = $name_item | Format-Wide

    # 공백 , newline 문자열을 버리고 이름만 추출
    $Site_Name = String $name_item
    $FTP_Site_Name_list += $Site_Name

    $Site_Path = 'IIS:\Sites\' + $Site_Name
    $FTP_Site_Path_list += $Site_Path

    # 드라이브 이름으로 시작하는 (EX : C\..) 실제 경로
    $Site_Path = (Get-WebFilePath $Site_Path).FullName
    $FTP_Site_Path_Full_Path_list += $Site_Path

}

#############################################################################################################


$index=0
$root_title="로그 관리"
$title=0
$result=0

#################################################### < 3 . 로그 관리 > ####################################################
#############################################################################################################################

########### 34. 로그의 정기적 검토 및 보고 ###########

$index="34"
$title="로그의 정기적 검토 및 보고"
$result = "수동"

$RV = "로그 , 응용 프로그램 및 시스템 로그 기록에 대해 정기적으로 검토 분석등이 이루어지는 경우"
$importance = "상"
$CV = "수동 확인"

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 35. 원격으로 액세스 할 수 있는 레지스트리 경로 ###########

$index="35"
$title="원격으로 액세스 할 수 있는 레지스트리 경로"

$RV = "RemoteRegistry Service를 사용하지 않는 경우"
$importance = "상"

$Service_Status = (Get-Service -Name "RemoteRegistry").Status

if($Service_Status -gt "Running")
{
    $result = "양호"
    $CV = "원격 레지스트리 서비스를 사용하고 있지 않습니다."
}
else
{
    $result = "취약"
    $CV = "원격 레지스트리 서비스를 사용하고 있지 있습니다."      
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 70. 이벤트 로그 관리 설정 ###########

$index="70"
$title="이벤트 로그 관리 설정"

$RV = "최대 로그 크기 10,240KB 이상 & '90일 이후 이벤트 덮어 씀' 설정" 
$importance = "하"
$CV = ""

$tempSTR = @(0,0,0)
$tempSTR_option = @(0,0,0)

# 응용 프로그램 로그 설정
$setting_option = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application" | Where-Object {$_.Name -eq "Retention"}).Value
$max_log_size = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Application" | Where-Object {$_.Name -eq "MaxSize"}).Value

if($setting_option -gt 0 -and ($max_log_size / 1024) -ge 10240)
{
    $result = "양호"
    $tempSTR[0] = ($max_log_size / 1024).toString() + "KB"
    $tempSTR_option[0] = 1
}
else
{
    $result = "취약"
    $tempSTR[0] = ($max_log_size / 1024).toString() + "KB"
    $tempSTR_option[0] = 0
}

# 보안 관련 로그 설정
$setting_option = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security" | Where-Object {$_.Name -eq "Retention"}).Value
$max_log_size = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\Security" | Where-Object {$_.Name -eq "MaxSize"}).Value

if($setting_option -gt 0 -and ($max_log_size / 1024) -ge 10240)
{
    $tempSTR[1] = ($max_log_size / 1024).toString() + "KB"
    $tempSTR_option[0] = 1
}
else
{
    $result = "취약"
    $tempSTR[1] = ($max_log_size / 1024).toString() + "KB"
    $tempSTR_option[0] = 0
}

# 시스템 관련 로그 설정
$setting_option = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System" | Where-Object {$_.Name -eq "Retention"}).Value
$max_log_size = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System" | Where-Object {$_.Name -eq "MaxSize"}).Value

if($setting_option -gt 0 -and ($max_log_size / 1024) -ge 10240)
{
    $tempSTR[2] = ($max_log_size / 1024).toString() + "KB"
    $tempSTR_option[0] = 1
}
else
{
    $result = "취약"
    $tempSTR[2] = ($max_log_size / 1024).toString() + "KB"
    $tempSTR_option[0] = 0
}

if($tempSTR_option[0] -eq 0)
{
    $CV += "응용 프로그램 관련 로그는 오래된 이벤트 우선 삭제X / 크기는 " + $tempSTR[0] + " 입니다." 
}
else
{
    $CV += "응용 프로그램 관련 로그는 오래된 이벤트 우선 삭제O / 크기는 " + $tempSTR[0] + " 입니다."   
}

if($tempSTR_option[1] -eq 0)
{
    $CV += "보안 관련 로그는 오래된 이벤트 우선 삭제X / 크기는 " + $tempSTR[1] + " 입니다." 
}
else
{
    $CV += "보안 관련 로그는 오래된 이벤트 우선 삭제O / 크기는 " + $tempSTR[1] + " 입니다."   
}

if($tempSTR_option[2] -eq 0)
{
    $CV += "시스템 관련 로그는 오래된 이벤트 우선 삭제X / 크기는 " + $tempSTR[2] + " 입니다." 
}
else
{
    $CV += "시스템 관련 로그는 오래된 이벤트 우선 삭제O / 크기는 " + $tempSTR[2] + " 입니다."   
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 71. 원격에서 이벤트 로그 파일 접근 차단 ###########

$index="71"
$title="원격에서 이벤트 로그 파일 접근 차단"

$RV = "로그 디렉토리의 접근 권한에 Everyone 권한이 없는 경우"
$importance = "중"

$Everyone_Access = (Get-Permissions -Path "C:\Windows\System32\config" | Where-Object {$_.IdentityReference -like "*Everyone*"}).Count
$Everyone_Access2 = (Get-Permissions -Path "C:\Windows\System32\LogFiles" | Where-Object {$_.IdentityReference -like "*Everyone*"}).Count      

if($Everyone_Access -eq 0 -and $Everyone_Access2 -eq 0)
{
    $result = "양호"
    $CV = "시스템 로그 디렉토리와 IIS 로그 디렉토리에 Everyone 권한이 존재하지 않습니다."
}
else
{
    if($Everyone_Access -gt 0 -and $Everyone_Access2 -gt 0)
    {
        $CV = "시스템 로그 , IIS 로그 디렉토리에 Everyone 권한이 존재합니다."
        $result = "취약"
    }
    elseif($Everyone_Access -gt 0)
    {
        $result = "취약"
        $CV = "시스템 로그에 Everyone 권한이 존재합니다."
    }
    elseif($Everyone_Access2 -gt 0)
    {
        $result = "취약"
        $CV = "IIS 로그 디렉토리에 Everyone 권한이 존재합니다."
    }
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt
 
###############################################

#############################################################################################################################