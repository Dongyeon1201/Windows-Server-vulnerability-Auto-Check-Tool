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

$index=0
$root_title="보안 관리"
$title=0
$result=0

#################################################### < 4 . 보안 관리 > ####################################################
#############################################################################################################################

########### 37. SAM 파일 접근 통제 설정 ###########

$index="37"
$title="SAM 파일 접근 통제 설정"

$RV = "SAM 파일 접근 권한에 Administrator , System 그룹만 모든 권한으로 설정되어 있는 경우"
$importance = "상"

$tempSTR = @()

$Access_sam = (Get-Permissions -Path "C:\Windows\System32\config\SAM").IdentityReference
$Count = 0

foreach($Nameitem in $Access_sam)
{
    $tempSTR += $Nameitem
    $tempSTR += ','

    if(!($Nameitem -like "*SYSTEM*" -or $Nameitem -like "*Administrator*"))
    {
        $Count++    
    }
}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

if($Count -eq 0)
{
    $result = "양호"
    $CV = "SAM 파일의 권한이 SYSTEM / Administrator 계정에만 부여되어 있습니다."
}
else
{
    $result = "취약"
    $CV = "SAM 파일에 권한이 존재하는 그룹 / 사용자는 " + $tempSTR + " 입니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 38. 화면보호기 설정 ###########

$index="38"
$title="화면보호기 설정"

$RV = "화면 보호기 설정 & 대기 시간 10분 이하 값 & 화면 보호기 해제를 위한 암호 사용 시"
$importance = "상"

$Timeout = (Get-RegistryValue "HKCU\Control Panel\Desktop\" | Where-Object {$_.Name -like "*ScreenSaveTimeOut*"}).Value
$Secure = (Get-RegistryValue "HKCU\Control Panel\Desktop\" | Where-Object {$_.Name -like "*ScreenSaveActive*"}).Value

if(($Timeout / 60) -le 10 -and $Secure -eq 1)
{
    $result = "양호"
    $CV = "화면 보호기 설정 O / 해제시 비밀번호 요청 O / 현재 대기 시간" + ($Timeout / 60).toString() + "분 입니다."
}
elseif($Timeout -eq $null -and $Secure -eq $null)
{
    $result = "취약"
    $CV = "화면 보호기가 기본 옵션으로 설정되어 있습니다."
}
else
{
    if(($Timeout / 60) -gt 10)
    {
        $result = "취약"
        $CV = "화면 보호기 설정O / 현재 대기 시간" + ($Timeout / 60).toString() + "분 입니다."
    }
    if($Secure -eq 0)
    {
        $result = "취약"
        $CV = "화면 보호기 설정O / 해제시 비밀번호 요청 X"
    }
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 39. 로그온 하지 않고 시스템 종료 허용 해제 ###########

$index="39"
$title="로그온 하지 않고 시스템 종료 허용 해제"

$RV = "'사용 안함' 옵션으로 설정"
$importance = "상"

$flag = (Get-RegistryValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Where-Object {$_.Name -eq "shutdownwithoutlogon"})

if($flag -eq 0)
{
    $result = "양호"
    $CV = "로그온 하지 않고 시스템 종료가 허용되지 않습니다."
}
else
{
    $result = "취약"
    $CV = "로그온 하지 않고 시스템 종료가 허용됩니다."   
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 40. 원격 시스템에서 강제로 시스템 종료 ###########

$index="40"
$title="원격 시스템에서 강제로 시스템 종료"

$RV = "해당 정책에 'Administrator'만 존재하는 경우"
$importance = "상"

$tempSTR = @()

$String_1 = Get-Content -Path ./user_rights | select-string -Pattern "SeRemoteShutdownPrivilege"
$String_1 = Out-String -InputObject $String_1

$String_1 = $String_1 -replace "`\s+",''

$String_2 = $String_1.Split("*,")
$SID_List = @()
$count = 0
for($X=1;$X -lt $String_2.count;$X++)
{
    if($String_2[$X].length -ne 0)
    {
        $SID_List += $String_2[$X]
    }
}

foreach($SID_ITEM in $SID_List)
{
    $flag = Convert_SID_TO_USERNAME $SID_ITEM

    $tempSTR += $flag
    $tempSTR += ','

    if(!($flag -like "*Administrator*"))
    {
        $count++
    }
}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}


if($count -eq 0)
{
    $result = "양호"
    $CV = "원격 시스템에서 강제로 시스템 종료 가능 정책에 Administrator 계정만 포함되어 있습니다."
}
else
{
    $result = "취약"
    $CV = $tempSTR + " 계정들이 원격 시스템에서 강제로 시스템 종료 가능 정책에 포함되어 있습니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 41. 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 해제 ###########

$index="41"
$title="보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 해제"

$RV = "해당 정책을 사용 하지 않을 경우"
$importance = "상"

$flag = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" | Where-Object {$_.Name -like "*crashonauditfail*"}).Value

if($flag -eq 0)
{
    $result = "양호"
    $CV = "'보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 옵션' 을 사용하지 않습니다."
}
else
{
    $result = "취약"
    $CV = "'보안 감사를 로그할 수 없는 경우 즉시 시스템 종료 옵션' 을 사용하는 중입니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 42. SAM 계정과 공유의 익명 열거 허용 안 함 ###########

$index="42"
$title="SAM 계정과 공유의 익명 열거 허용 안 함"

$RV = "해당 정책을 사용하지 않을 경우"
$importance = "상"

$flag = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\" | Where-Object {$_.Name -eq "restrictanonymous"}).Value

if($flag -eq 0)
{
    $result = "취약"
    $CV = "'SAM 계정과 공유의 익명 열거 허용 안 함' 을 사용하지 않습니다."
}
else
{
    $result = "양호"
    $CV = "'SAM 계정과 공유의 익명 열거 허용 안 함' 을 사용하는 중입니다." 
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 43. Autologin 기능 제어 ###########

$index="43"
$title="Autologin 기능 제어"

$RV = "AutoAdminLogon 값이 없거나 0으로 설정되어 있는 경우"
$importance = "상"

$flag = Test-RegistryValue "HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogon" "AutoAdminLogon"

if($flag)
{
    $flag = (Get-RegistryValue "HKLM\SOFTWARE\Microsoft\WindowsNT\CurrentVersion\Winlogin" | Where-Object {$_.Name -eq "AutoAdminLogon"}).Value
    
    if($flag -eq 1)
    {
        $result = "취약"
        $CV = "AutoAdminLogon 기능을 사용하는 중입니다."
    }
    else
    {
        $result = "양호"
        $CV = "AutoAdminLogon 기능을 사용하지 않습니다."
    }
}
else
{
    $result = "양호"
    $CV = "AutoAdminLogon 기능을 사용하지 않습니다."
} 

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 44.이동식 미디어 포맷 및 꺼내기 허용 ###########

$index="44"
$title="이동식 미디어 포맷 및 꺼내기 허용"

$RV = "해당 옵션 정책이 'Administrator' 로 설정되어 있는 경우"
$importance = "상"

$flag = Test-RegistryValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" "AllocateDASD"

if($flag)
{
    $flag = (Get-RegistryValue "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" | Where-Object {$_.Name -eq "AllocateDASD"}).Value
    
    if($flag -eq 0)
    {
        $result = "양호"
        $CV = "Administrator"
    }
    elseif($flag -eq 1)
    {
        $result = "취약"
        $CV = "Administrator 및 Power Users"
    }
    elseif($flag -eq 2)
    {
        $result = "취약"
        $CV = "Administrator 및 Interactive Users"
    }
}
else
{
    $result = "취약"
    $CV = "'이동식 미디어 포맷 및 꺼내기 허용' 옵션의 설정값을 지정하지 않았습니다."
} 

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 45. 디스크 볼륨 암호화 설정 ###########

$index="45"
$title="디스크 볼륨 암호화 설정"
$result = "수동"

$RV = "'데이터 보호를 위해 내용을 암호화' 정책을 선택"
$importance = "상"

$CV = "수동 점검"


echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 72. DoS 공격 방어 레지스트리 설정 ###########

$index="72"
$title="DoS 공격 방어 레지스트리 설정"

$RV = "DoS 방어 레지스트리 값을 적절하게 설정"
$importance = "중"

$tempSTR = @(0,0,0,0)
$CV = ""

$Reg_Path = "HKLM\System\CurrentControl\Set\Services\Tcpip\Parameters\"

$flag = Test-RegistryValue $RegPath "SynAttackProtect"
if($flag)
{
    $SynAP_Value =  (Get-RegistryValue $RegPath | Where-Object {$_.Name -eq "SynAttackProtect"}).Value
}

$flag = Test-RegistryValue $RegPath "EnableDeadGWDetect"
if($flag)
{
    $EnableDGWD_Value =  (Get-RegistryValue $RegPath | Where-Object {$_.Name -eq "EnableDeadGWDetect"}).Value
}

$flag = Test-RegistryValue $RegPath "KeepAliveTime"
if($flag)
{
    $KeepAT_Vaule =  (Get-RegistryValue $RegPath | Where-Object {$_.Name -eq "KeepAliveTime"}).Value
}

$flag = Test-RegistryValue $RegPath "NoNameReleaseOnDemand"
if($flag)
{
    $NoNameROD_Value =  (Get-RegistryValue $RegPath | Where-Object {$_.Name -eq "NoNameReleaseOnDemand"}).Value
}

############

if($SynAP_Value -eq $null -or $SynAP_Value -eq 0)
{
    $result = "취약"
    $tempSTR[0] = "현재 SynAttack 프로텍션을 사용하지 않습니다."
}
else
{
    if($SynAP_Value -eq 1)
    {
        $tempSTR[0] = "현재 SynAttackProtect 값은 1이며, 재전송 시간 감소 / route 캐쉬 엔트리를 지연시키는 방어 기능이 적용된 상태이다."
    }
    elseif($SynAP_Value -eq 2)
    {
        $tempSTR[0] = "현재 SynAttackProtect 값은 2이며, 재전송 시간 감소 / route 캐쉬 엔트리를 지연 / Winsock에 대한 지시를 지연시키는 방어 기능이 적용된 상태이다."
    }
}

if($EnableDGWD_Value -eq $null)
{
    $result = "취약"
    $tempSTR[1] = "현재 EnableDeadGWDetect 값을 설정하지 않았습니다."
}
else
{
    if($EnableDGWD_Value -eq 1)
    {
        $tempSTR[1] = "현재 EnableDeadGWDetect 값은 1이며, 작동하지 않는 Gateway를 검색할 수 있는 상태이다."
    }
    else
    {
        $result = "취약"
        $tempSTR[1] = "현재 EnableDeadGWDetect 값은 1이며, 작동하지 않는 Gateway를 검색할 수 없는 상태이다."
    }
}

if($KeepAT_Vaule -eq $null)
{
    $result = "취약"
    $tempSTR[2] = "현재 KeepAliveTime 값을 설정하지 않았습니다."
}
else
{
    if($KeepAT_Vaule -eq 300000)
    {
       $tempSTR[2] = "현재 KeepAliveTime 값은 300000(5분)이며, 5분에 한번씩 Keep-alive 패킷을 전송합니다."
    }
    else
    {
        $result = "취약"
        $tempSTR[2] = "현재 KeepAliveTime 값은 " + $KeepAT_Vaule.toString() + " 이며, "+ ($KeepAT_Vaule / 6000).toString() +"분에 한번씩 Keep-alive 패킷을 전송합니다."
    }
}

if($NoNameROD_Value -eq $null)
{
    $result = "취약"
    $tempSTR[3] = "현재 NoNameReleaseOnDemand 값을 설정하지 않았습니다."
}
else
{
    if($NoNameROD_Value -eq 1)
    {
        $tempSTR[3] = "현재 NoNameReleaseOnDemand 기능을 사용하는 중입니다."
    }
    else
    {
        $result = "취약"
        $tempSTR[3] = "현재 NoNameReleaseOnDemand 기능을 사용하지 않습니다."
    }
}

foreach($item in $tempSTR)
{
    $CV += $item
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 73. 사용자가 프린터 드라이버를 설치할 수 없게 함 ###########

$index="73"
$title="사용자가 프린터 드라이버를 설치할 수 없게 함"

$RV = "해당 정책을 사용 하는 경우"
$importance = "중"

$flag = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" | Where-Object {$_.Name -eq "AddPrinterDrivers"}).Value
    
if($flag -eq 1)
{
    $result = "양호"
    $CV = "'사용자가 프린터 드라이버를 설치할 수 없게 함' 기능을 사용하는 중입니다."
}
else
{
    $result = "취약"
    $CV = "'사용자가 프린터 드라이버를 설치할 수 없게 함' 기능을 사용하지 않습니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 74. 세션 연결을 중단하기 전에 필요한 유휴시간 ###########

$index="74"
$title="세션 연결을 중단하기 전에 필요한 유휴시간"

$tempSTR = @(0,0)

$RV = "'로그온 시간이 만료되면 클라이언트 연결 끊기 정책' 사용 & '세션 연결을 중단하기 전에 필요한 유휴시간 15분' 설정"
$importance = "중"

$flag_active = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | Where-Object {$_.Name -eq "enableforcedlogoff"}).Value
$flag_time = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" | Where-Object {$_.Name -eq "autodisconnect"}).Value

if($flag_active)
{
    $result = "양호"
    $tempSTR[0] = "'로그온 시간이 만료되면 클라이언트 연결 끊기' 정책을 사용 중 입니다."
}
else
{
    $result = "취약"
    $tempSTR[0] = "'로그온 시간이 만료되면 클라이언트 연결 끊기' 정책을 사용하고 있지 않습니다."
}

if($flag_time -eq 15)
{
    $tempSTR[1] = "15"
}
else
{
    $result = "취약"
    $tempSTR[1] = $flag_time.toString()
}

$CV = $tempSTR[0] + "유휴 시간이 " + $tempSTR[1] + "분으로 설정되어 있습니다." 

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 75. 경고 메세지 설정 ###########

$index="75"
$title="경고 메세지 설정"

$RV = "로그인 경고 메세지 제목 및 내용이 설정되어 있는 경우"
$importance = "하"

$tempSTR = @(0,0)

$flag_title = (Get-RegistryValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Where-Object {$_.Name -eq "legalnoticecaption"}).Value
$flag_text = (Get-RegistryValue "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Where-Object {$_.Name -eq "legalnoticetext"}).Value

if($flag_title.length -eq 0)
{
    $result = "취약"
    $tempSTR[0] = "로그인 경고 제목이 설정되어 있지 않습니다."
}
else
{
    $result = "양호"
    $tempSTR[0] = "설정된 로그인 경고 제목은 '"+ $flag_title +"' 입니다."
}

if($flag_text.length -eq 0 -or $flag_text -eq '')
{
    $result = "취약"
    $tempSTR[1] = "로그인 경고 내용이 설정되어 있지 않습니다."
}
else
{
    $tempSTR[1] = "설정된 로그인 경고 내용은 '"+ $flag_text +"' 입니다."
}

$CV = $tempSTR[0] + $tempSTR[1]

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 76. 사용자별 홈 디렉토리 권한 설정 ###########

$index="76"
$title="사용자별 홈 디렉토리 권한 설정"

$RV = "홈 디렉토리에 Everyone 권한이 없는 경우"
$importance = "중"

$tempSTR = @()
$total_count = 0

$User_List = (Get-Localuser).Name
$User_Home_DIR = @()

foreach($user_item in $User_List)
{
    $User_Home_DIR += 'C:\Users\' + $user_item
}

for($X=0;$X -lt $User_Home_DIR.Count;$X++)
{
    $flag = Test-Path -Path $User_Home_DIR[$X]

    if($flag)
    {
        $Everyone_Access_count = (Get-Permissions -Path $User_Home_DIR[$X] | Where-Object {$_.IdentityReference -like "*Everyone*"}).Count
        if($Everyone_Access_count -gt 0)
        {
            $tempSTR += $User_List[$X]
            $tempSTR += ','

            $total_count++
        }
    }
}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

if($total_count -gt 0)
{
    $CV = $tempSTR + "사용자 홈 디렉토리에서 Everyone 권한 존재"
}
else
{
    $CV = "홈 디렉토리에 Everyone 권한을 가진 사용자는 존재X"
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 77. LAN Manager 인증 수준 ###########

$index="77"
$title="LAN Manager 인증 수준"

$RV = "인증 수준을 'NTLMv2 응답만 보냄' 으로 설정"
$importance = "중"

$flag = Test-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" "LmComPatibilityLevel"
if($flag)
{
    $flag = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" | Where-Object {$_.Name -eq "LmComPatibilityLevel"}).Value
    if($flag -eq 3)
    {
        $result = "양호"
        $CV = "현재 LAN Manager 인증 수준은 'NTLMv2' 입니다."
    }
    else
    {
        $result = "취약"

        switch($flag){
            0 {$CV = "현재 LAN Manager 인증 수준은 'NTLMv2' 입니다."}
            1 {$CV = "현재 LAN Manager 인증 수준은 'LM 및 NTLM 응답 보내기 - 협상되면 NTLMv2 세션 보안 사용'"}
            2 {$CV = "현재 LAN Manager 인증 수준은 'NTLM 응답만 보내기' 입니다."}
            4 {$CV = "현재 LAN Manager 인증 수준은 'NTLMv2 응답만 보내기 및 LM 거부' 입니다."}
            5 {$CV = "현재 LAN Manager 인증 수준은 'NTLMv2 응답만 보냅니다. LM 및 NTLM은 거부합니다.'"}
            default{}
        }
    }
}
else
{
    $result = "취약"
    $CV = "LAN Manager 인증 수준을 설정하지 않았습니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 78. 보안 채널 데이터 디지털 암호화 또는 서명 ###########

$index="78"
$title="보안 채널 데이터 디지털 암호화 또는 서명"

$RV = "도메인 구성원 정책 중 '보안 채널 데이터를 디지털 암호화 또는, 서명' / '보안 채널 데이터 디지털 암호화(가능한 경우)' / '보안 채널 데이터 서명(가능한 경우)' 정책이 '사용' 상태인 경우"
$importance = "중"

$tempSTR = @()

$flag_1 = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Where-Object {$_.Name -eq "RequireSignOrSeal"}).Value
$flag_2 = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Where-Object {$_.Name -eq "SealSecureChannel"}).Value
$flag_3 = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Where-Object {$_.Name -eq "SignSecureChannel"}).Value

if($flag_1 -eq 1 -and $flag_2 -eq 1 -and $flag_3 -eq 1)
{
    $result = "양호"
    $CV = "3가지 정책 모두 사용 중"
}
else
{
    if($flag_1 -eq 0)
    {
        $result = "취약"
        $tempSTR += "'보안 채널 데이터를 디지털 암호화 또는, 서명' 정책"
        $tempSTR += ','
    }
    if($flag_1 -eq 0)
    {
        $result = "취약"
        $tempSTR += "'보안 채널 데이터 디지털 암호화' 정책"
        $tempSTR += ','
    }
    if($flag_1 -eq 0)
    {
        $result = "취약"
        $tempSTR += "'보안 채널 데이터 서명' 정책"
        $tempSTR += ','
    }

    if($tempSTR.count -gt 0)
    {
        $tempSTR[-1] = ''
    }

    $CV = $tempSTR + "을 사용하고 있지 않습니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 79. 파일 및 디렉토리 보호 ###########

$index="79"
$title="파일 및 디렉토리 보호"

$RV = "NTFS 파일 시스템을 사용"
$importance = "중"

$tempSTR = @()

$Not_NTFS_Count = (Get-Volume | Where-Object {$_.OperationalStatus -eq "OK"} | Where-Object {$_.DriveLetter} | Where-object {$_.FileSystem -ne "NTFS"}).Count

if($Not_NTFS_Count -gt 0)
{
    $result = "양호"
    
    $Not_NTFS_list = (Get-Volume | Where-Object {$_.OperationalStatus -eq "OK"} | Where-Object {$_.DriveLetter}).DriveLetter | Where-object {$_.FileSystem -ne "NTFS"}
    
    foreach($item in $Not_NTFS_list)
    {
        $tempSTR += $item
        $tempSTR += ','
    }

    if($tempSTR.count -gt 0)
    {
        $tempSTR[-1] = ''
    }

    $CV = "NTFS 파일 시스템을 사용하지 않는 드라이브는 " + $tempSTR + " 드라이브 입니다."
}
else
{
    $result = "양호"
    $CV = "활성화된 드라이브중 NTFS 파일 시스템을 사용하지 않는 드라이브는 없습니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 80. 컴퓨터 계정 암호 최대 사용 기간 ###########

$index="80"
$title="컴퓨터 계정 암호 최대 사용 기간"

$RV = "'컴퓨터 계정 암호 변경 사용 안 함' 정책을 사용하지 않으며, '컴퓨터 계정 암호 최대 사용기간'이 90일로 설정"
$importance = "중"

$CV = @()

$flag_1 = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Where-Object {$_.Name -eq "DisablePasswordChange"}).Value
$flag_2 = (Get-RegistryValue "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" | Where-Object {$_.Name -eq "MaximumPasswordAge"}).Value

if($flag_1 -eq 0)
{
    $result = "양호"
    $CV += "'컴퓨터 계정 암호 변경 사용 안 함' 정책을 사용하지 않으며, "
}
else
{
    $result = "취약"
    $CV += "'컴퓨터 계정 암호 변경 사용 안 함' 정책을 사용하며, "
}

if($flag_2 -eq 90)
{
    $CV += "컴퓨터 계정 암호 최대 사용 기간이 90일로 설정"
}
elseif($flag_2 -gt 90)
{
    $result = "취약"
    $CV += "컴퓨터 계정 암호 최대 사용 기간이 " + $flag_2.toString() + "일로 설정"
}
else
{
    $CV += "컴퓨터 계정 암호 최대 사용 기간이 " + $flag_2.toString() + "일로 설정"
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 81. 시작프로그램 목록 분석 ###########

$index="81"
$title="시작프로그램 목록 분석"

$RV = "시작 프로그램을 정기적으로 검사한다."
$importance = "중"

$Start_program_count = (Get-RegistryValue "hkcu\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object Name,Value | Format-List).count

if($Start_program_count -eq 0)
{
    $result = "양호"
    $CV = "등록된 시작 프로그램이 존재하지 않습니다."
}
else
{
    $result = "수동"
    echo("--------------- 시작 프로그램 목록 ---------------") > 81_Start_Program_List.txt
    Get-RegistryValue "hkcu\Software\Microsoft\Windows\CurrentVersion\Run" | Select-Object Name,Value | Format-List >> 81_Start_Program_List.txt

    $CV = "수동 확인"

}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 82. Windows 인증 모드 사용 ###########

$index="82"
$title="Windows 인증 모드 사용"
$result = "수동"

$RV = "DB 로그인 시, Windos 인증 모드 사용 / sa 계정 비 활성화 / sa 계정 사용시 강력한 암호정책 사용"
$importance = "중"

$CV = "수동 점검"

#HKEY_LOCAL_MACHINE\Software\Microsoft\Microsoft SQL Server\<Instance Name>\MSSQLServer\LoginMode
# 1 : Windwos 인증만
# 2 : 혼합 모드 인증

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

#############################################################################################################################
