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


#관리자 계정으로 점검하는지 확인

$Current = Test-Role "Administrator"

if(!$Current)
{
    exit 5
}

# 검사에 필요한 명령문을 사용하기 위한 Module Import
$Use_Module_List = @("WebAdministration","ActiveDirectory","DnsServer","PSWindowsUpdate")

#모듈 설정

foreach($module_item in $Use_Module_List)
{
    if((Get-Module -Name $module_item).count -ne 0)
    {

        try
        {
            # 모듈을 사용한다.
            Import-Module -Name $module_item -Force
        }
        catch
        {
            # 만약 사용할 모듈이 설치되어 있지 않다면 해당 모듈을 설치한다.
            Install-Module -Name $module_item -Force 
        }
    }
}


SecEdit /export /cfg ./user_rights

# 문서화를 위한 결과 저장 변수
$index=0
$root_title="계정 관리"
$title=0
$result=0

#Recommanded Value
$RV = 0

#Current value
$CV = 0

#비고란
$importance = 0

echo ("번호#분류#내용#상태") > check_result.txt
#echo ("번호#분류#내용#권장 값#현재 설정 값#상태#중요도") > check_result_more.txt

############################################# < 1 . 계정 관리 취약점 항목 점검> #############################################

#############################################################################################################################

$index="01"
$title="계정 관리 취약점 항목 점검"

try{
    $Active_DIR_Service = Get-ADDefaultDomainPasswordPolicy
}
catch
{
    $Active_DIR_Service = 0
}

###### 1. Administrator 계정 이름 바꾸기 ######   

$RV = "Administrator가 아닌 다른 값"
$importance = "상"

$var = (Get-LocalUser Administrator).length

if($var -gt 0)
{
    $result = "취약"

    $CV = "Administrator"
}
else
{
    $result = "양호"

    $f1 = (Get-LocalGroupMember -Name "Administrators").Name
    $f1 = Out-String -InputObject $f1
    $f1 = $f1.Split("\")
    $CV = $f1[-1]
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) > check_result_more.txt

###############################################

############# 2. Guest 계정 상태 ##############

$index="02"
$title="Guest 계정 상태"

$RV = "Guest 계정 비활성화"
$importance = "상"

$var = Get-LocalUser -Name Guest | Select-Object Enabled | Format-Wide

if($var -eq 'True')
{
    $result = "취약"

    $CV = "Guest 계정 활성화"
}
else
{
    $result = "양호"

    $CV = "Guest 계정 비활성화"
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

############ 3. 불필요한 계정 제거 ############

$index="03"
$title="불필요한 계정 제거"
$result="수동"

$RV = "Guest 계정 비활성화"
$importance = "상"
$CV = "활성화된 계정들 중 불필요한 계정은 삭제하여 주세요."

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 4. 계정 잠금 임계값 설정 ###########

$index="04"
$title="계정 잠금 임계값 설정"

$RV = "5이하"
$importance = "상"

$tempStr = Get-Content user_rights | Select-String "LockoutBadCount"
$tempStr = Out-String -InputObject $tempStr
$tempStr = $tempStr.Split('=')
$count = $tempStr[-1]


if($count)
{
    if($count -eq 0)
    {
        $result = "취약"
        $CV = $count
        $CV = $CV.Trim()
        $CV = "계정 잠금 임계값 미 설정"
    }
    elseif($count -le 5)
    {
        $result = "양호"
        $CV = $count
        $CV = $CV.Trim()
        $CV = "현재 계정 잠금 임계값은 " + $CV + "회"
    }
    elseif($count -ge 6)
    {
        $result = "취약"
        $CV = $count
        $CV = $CV.Trim()
        $CV = "현재 계정 잠금 임계값은 " + $CV + "회"
    }
}
else
{
    $result = "취약"
    $CV = "계정 잠금 임계값이 설정되어 있지 않습니다."
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

###### 5. 해독 가능한 암호화를 사용하여 암호 저장 해제 ######

$index="05"
$title="해독 가능한 암호화를 사용하여 암호 저장 해제"

$RV = "사용 안 함"
$importance = "상"

$tempStr = Get-Content user_rights | Select-String "PasswordComplexity"
$tempStr = Out-String -InputObject $tempStr
$tempStr = $tempStr.Split('=')
$count = $tempStr[-1]


if($count)
{
    $result = "취약"
    $CV = "해당 옵션 사용 중"
}
else
{
    $result = "양호"
    $CV = "해당 옵션 사용 안 함"
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

###### 6. 관리자 그룹에 최소한의 사용자 포함 ######

$index="06"
$title="관리자 그룹에 최소한의 사용자 포함"
$result = "수동"

$tempStr = @()

$RV = "구성원 1명 이하로 유지 / 불필요한 관리자 계정 존재 X"
$importance = "상"

foreach($item in (Get-LocalGroupMember -Name Administrators).Name)
{
    $item = $item.Split('\')
    $item = $item[-1]
    $tempStr += $item
    $tempStr += ',' 
}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

$CV = $tempStr

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

###### 46. Everyone 사용권한을 익명사용자에 적용 해제 ######

$index="46"
$title="Everyone 사용권한을 익명사용자에 적용 해제"

$RV = "사용 안 함"
$importance = "중"

$RegPath = "HKLM:SYSTEM\CurrentControlSet\Control\Lsa"
#$RegPath = "HKLM:SYSTEM\CurrentSet1\Control\Lsa"
$Name = "everyoneincludesanonymous"

$var = Get-ItemPropertyValue -Path $RegPath -Name $Name

if(!$var)
{
    $result = "양호"
    $CV = "Everyone 사용권한을 익명사용자에 적용 해제"
}
else
{
    $result = "취약"
    $CV = "Everyone 사용권한을 익명사용자에 적용"
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 47. 계정 잠금 기간 설정 ###########

$index="47"
$title="계정 잠금 기간 설정"

$RV = "60(분)이상"
$importance = "중"

$tempStr = Get-Content user_rights | Select-String "LockoutDuration"
$tempStr = Out-String -InputObject $tempStr
$tempStr = $tempStr.Split('=')
$count = $tempStr[-1]


if($count)
{
    if($count -ge 60)
    {
        $result = "양호"
        $CV = $count.ToString() + "분"
    }
    else
    {
        $result = "취약"
        $CV = $count.ToString() + "분"
    }
}
else
{
    $result = "취약"
    $CV = "값이 설정되어 있지 않습니다."
}

# 1) Get-ADDefaultDomainPasswordPolicy 명령어를 입력한다
# 2) LockoutDuration , LockoutObsercationWindow 값을 확인 한다

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 48. 패스워드 복잡성 설정 ##########

$index="48"
$title="패스워드 복잡성 설정"

$RV = "사용"
$importance = "중"

$tempStr = Get-Content user_rights | Select-String "PasswordComplexity"
$tempStr = Out-String -InputObject $tempStr
$tempStr = $tempStr.Split('=')
$count = $tempStr[-1]


if($count)
{
    $result = "양호"
    $CV = "해당 옵션 사용 중"
}
else
{
    $result = "취약"
    $CV = "해당 옵션 사용 안 함"
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

######## 49. 패스워드 최소 암호 길이 ##########

$index="49"
$title="패스워드 최소 암호 길이"

$RV = "8(자)이상"
$importance = "중"

$tempStr = Get-Content user_rights | Select-String "MinimumPasswordLength"
$tempStr = Out-String -InputObject $tempStr
$tempStr = $tempStr.Split('=')
$count = $tempStr[-1]


if($count)
{
    if($count -ge 8)
    {
        $result = "양호"
        $CV = $count
        $CV = $CV.Trim()
        $CV += "자"
    }
    else
    {
        $result = "취약"
        $CV = $count
        $CV = $CV.Trim()
        $CV += "자"
    }
}
else
{
    $result = "취약"
    $CV = "해당 옵션이 설정되어 있지 않습니다."
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

######### 50. 패스워드 최대 사용 기간 #########

$index="50"
$title="패스워드 최대 사용 기간"

$RV = "90(일)이하"
$importance = "중"

$tempStr = Get-Content user_rights | Select-String "MaximumPasswordAge = "
$tempStr = Out-String -InputObject $tempStr
$tempStr = $tempStr.Split('=')
$count = $tempStr[-1].Trim()

if($count)
{
    if($count -le 90)
    {
        $result = "양호"
        $CV = $count
        $CV = $CV.Trim()
        $CV += "일"
    }
    else
    {
        $result = "취약"
        $CV = $count
        $CV = $CV.Trim()
        $CV += "일"
    }
}
else
{
    $result = "취약"
    $CV = "해당 옵션이 설정되어 있지 않습니다."
}

# 1) Get-ADDefaultDomainPasswordPolicy 명령어를 입력한다
# 2) MaxPasswordAge 값을 확인한다

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

######### 51. 패스워드 최소 사용 기간 #########

$index="51"
$title="패스워드 최소 사용 기간"

$RV = "0보다 큰 값"
$importance = "중"

$tempStr = Get-Content user_rights | Select-String "MinimumPasswordAge"
$tempStr = Out-String -InputObject $tempStr
$tempStr = $tempStr.Split('=')
$count = $tempStr[-1]


if($count)
{
    if($count -gt 0)
    {
        $result = "양호"
        $CV = $count
        $CV = $CV.Trim()
        $CV += "일"
    }
    else
    {
        $result = "취약"
        $CV = $count
        $CV = $CV.Trim()
        $CV += "일"
    }
}
else
{
    $result = "취약"
    $CV = "설정X"
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

###### 52. 마지막 사용자 이름 표시 안 함 ######

$index="52"
$title="마지막 사용자 이름 표시 안 함"

$RV = "사용"
$importance = "중"

$RegPath = "HKLM:Software\Microsoft\Windows\CurrentVersion\Policies\System"
$Name = "dontdisplaylastusername"

$var = Get-ItemPropertyValue -Path $RegPath -Name $Name

if($var)
{
    $result = "양호"
    $CV = "해당 옵션 사용 중"
}
else
{
    $result = "취약"
    $CV = "해당 옵션 사용 안 함"
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

############# 53. 로컬 로그온 허용 ############

$index="53"
$title="로컬 로그온 허용"

$RV = "Administrator, IUSR_ 만 존재"
$importance = "중"
$CV = @()

$String_1 = Get-content ./user_rights | Select-String "SeInteractiveLogonRight"
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

    $flag = Out-String -InputObject $flag
    $flag = $flag.Split('\')
    $flag = $flag[-1].Trim()

    $CV += $flag
    $CV += ','

    if(!($flag -like "*Administrator*" -or $flag -like "*IUSR*"))
    {
        $count++
    }
}

$CV[-1] = ''

if($count -eq 0)
{
    $result = "양호"
}
else
{
    $result = "취약"
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

###### 54. 익명 SID/ 이름 변환 허용 해제  ######

$index="54"
$title="익명 SID/ 이름 변환 허용 해제"

$RV = "사용 안 함"
$importance = "중"

$flag = (Get-content ./user_rights | Select-String "LSAAnonymousNameLookup" | Select-String "0").count

if($flag -eq 0)
{
    $result = "취약"
    $CV = "해당 옵션 사용 중"

}
else
{
    $result = "양호"
    $CV = "해당 옵션 사용 안 함"
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

############## 55. 최근 암호 기억 ##############

$index="55"
$title="최근 암호 기억"

$RV = "4(개)이상"
$importance = "중"

$tempStr = Get-Content user_rights | Select-String "PasswordHistorySize"
$tempStr = Out-String -InputObject $tempStr
$tempStr = $tempStr.Split('=')
$count = $tempStr[-1]

if($count)
{
    if($count -ge 4)
    {
        $result = "양호"
        $CV = $count
        $CV = $CV.Trim()
        $CV += "개"
    }
    else
    {
        $result = "취약"
        $CV = $count
        $CV = $CV.Trim()
        $CV += "개"
    }
}
else
{
    $result = "취약"
    $CV = "해당 옵션이 설정되어 있지 않습니다."
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

###### 56. 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한 ######

$index="56"
$title="콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한"

$RV = "사용"
$importance = "중"

$RegPath = "HKLM:SYSTEM\CurrentControlSet\Control\Lsa"
$Name = "LimitBlankPasswordUse"

$var = Get-ItemPropertyValue -Path $RegPath -Name $Name

if($var)
{
    $result = "양호"
    $CV = "해당 옵션 사용 중"
}
else
{
    $result = "취약"
    $CV = "해당 옵션 사용 안 함"
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

###### 57. 원격터미널 접속 가능한 사용자 그룹 제한 ######

$index="57"
$title="원격터미널 접속 가능한 사용자 그룹 제한"

$RV = "관리자가 아닌 별도의 원격접속 계정이 존재"
$importance = "중"
$CV = @()

$var =  (Get-LocalGroupMember -Group "Remote Desktop Users").length

if($var -eq 0)
{
    $result = "취약"
    $CV = "별도 계정 존재X"
}
else
{
    $tempStr = (Get-LocalGroupMember -Group "Remote Desktop Users").Name

    foreach($item in $tempStr)
    {
        $item = Out-String -InputObject $item
        $item = $item.Split('\')
        $Name = $item[-1].Trim()

        $CV += $Name
        $CV += ','
    }

    if($CV.count -gt 0)
    {
        $CV[-1] = ''
    }

    $result = "양호"
    $CV = $CV.Trim()
}

echo($index + '#' + $root_title + '#' + $title + '#' + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

#############################################################################################################################
