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

# 문서화를 위한 결과 저장 변수
$index=0
$root_title="서비스 관리"
$title=0
$result=0

#################################################### < 2 . 서비스 관리 > ####################################################
#############################################################################################################################

#################### IIS 서비스 관련 취약점 점검에 자주 사용되는 IIS 버전은 미리 구해둔다. ####################
try{
$IIS_version = Get-ItemProperty HKLM:\SOFTWARE\Microsoft\InetStp\  | select setupstring | Format-Wide

# Object형 결과 값 String형으로 변환
$IIS_version = Out-String -InputObject $IIS_version

# "IIS xxx" 부분에서 숫자 부분 출력
$IIS_version = $IIS_version.Split(" ")[1]

# String형 값 -> INT 형으로 바꾸기
$IIS_version = $IIS_version -as [int]
}
catch{}
#############################################################################################################

#################### IIS 사이트 이름과 경로는 자주 점검에 자주 사용되므로 미리 구해둔다. ####################

$IIS_Site_List = Get-IISSite | select-Object Name

$Site_Name_list=@()
$Site_Path_list=@()
$Site_Path_Full_Path_list=@()

foreach($name_item in $IIS_Site_List)
{
    $name_item = $name_item | Format-Wide

    # 공백 , newline 문자열을 버리고 이름만 추출
    $Site_Name = String $name_item
    $Site_Name_list += $Site_Name

    $Site_Path = 'IIS:\Sites\' + $Site_Name
    $Site_Path_list += $Site_Path

    # 드라이브 이름으로 시작하는 (EX : C\..) 실제 경로
    $Site_Path = (Get-WebFilePath $Site_Path).FullName
    $Site_Path_Full_Path_list += $Site_Path

}

#############################################################################################################

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

###### 7. 공유 권한 및 사용자 그룹 설정 ######

$index="07"
$title="공유 권한 및 사용자 그룹 설정"

$RV = "일반 공유 디렉토리 X / 접근 권한에 Everyone 권한이 없음"
$importance = "상"

# 모든 공유 폴더 중 Everyone으로 공유 된 폴더 정보를 조회
$SmbShareInfo = Get-SmbShare | foreach {Get-SmbShareAccess -Name $_.Name} | Where-Object {$_.AccountName -like 'Everyone'}
$var = $SmbShareInfo.Length
$CV = @()

$temp = $SmbShareInfo.Name

if($var -gt 0)
{
    $result = "취약"
    foreach($item in $temp)
    {
        $CV += ($item + ',')
    }
    $CV[-1] = "공유 폴더가 Everyone 권한으로 공유 중"

}
else
{
    $result = "양호"
    $CV = "존재X"
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

###### 8. 하드디스크 기본 공유 제거 취약 ######

$index="08"
$title="하드디스크 기본 공유 제거 취약"

$RV = "AutoShareServer 값이 0 & 기본 공유가 존재X"
$importance = "상"

# IPC$를 제외한 기본 공유 폴더가 존재하는지 확인
$DefaultSmbInfo = Get-SmbShare | Where-Object {$_.Name -ne "IPC$"} |Where-Object {$_.Name -like "*$"}
$var = $DefaultSmbInfo.Length

$RegPath = "HKLM:SYSTEM\CurrentControlSet\Services\LanmanServer\AutotunedParameters"
$Name = "AutoShareServer"

try{
    $REGvar = Get-ItemPropertyValue -Path $RegPath -Name $Name
}
catch
{
}

if($var -gt 0)
{
    $result = "취약"
    $CV = "기본 공유 폴더가 존재하며, "
}
else
{
    $result = "양호"
    $CV = "기본 공유 폴더가 존재하지 않으며, "
}

if($REGvar -eq 0)
{
    $CV += "AutoShareServer 값은 0"
}
elseif($REGvar -eq 1)
{
    $result = "취약"
    $CV += "AutoShareServer 값은 1"
}
else
{
    $result = "취약"
    $CV += "AutoShareServer 값 설정X"
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 9. 불필요한 서비스 제거 ###########

$index="09"
$title="불필요한 서비스 제거"

$RV = "일반적으로 불필요한 서비스들을 중지"
$importance = "상"

# 일반적으로 불필요한 서비스 목록 (KISA 문서 참고)
$Needless_Services = @("Alerter","Automatic Updates","Clipbook","Computer Browser","Cryptographic Services","DHCP Client",
"Distributed Link Tracking","DNS Client","Error reporting Service","Human Interface Device Access","IMAPU CD-Buming COM Service",
"Messenger","NetMeeting Remote Desktop Sharing","Portable Media Serial Number","Print Spooler","Remote Registry","Simple TCP/IP Services",
"Wireless Zero Configuration")

$count = 0
$tempSTR = @()
 
foreach($item in $Needless_Services)
{
    echo ($item) >> Needless_Services_list.txt    
    $var = Get-Service | Where-Object {$_.Status -eq 'Running'} | Where-Object {$_.DisplayName -like $item} | Format-List
    if($var.length -gt 0)
    {
        $tempSTR += $item
        $tempSTR += ','

        $count++
    }
}
if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

if($count -gt 0)
{
    $result = "취약"
    $CV = "구동중인 불필요한 서비스의 목록은 " + $tempSTR
}
else 
{
    $result = "양호"
    $CV = "구동중인 불필요한 서비스가 존재하지 않습니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 10 .IIS 서비스 구동 점검 ##########

$index="10"
$title="IIS 서비스 구동 점검"
$result = "수동"

$RV = "IIS 서비스를 사용하지 않는 경우엔 중지"
$importance = "상"

$IIS_Services = @("IIS Admin Service","FTP Publishing Service","World Wide Web Publishing Service","Windows Process Activation Service")

$count = 0

$tempSTR = @()


foreach($item in $IIS_Services)
{
    $var = Get-Service | Where-Object {$_.Status -eq 'Running'} | Where-Object {$_.DisplayName -like $item} | Format-List
    if($var.length -gt 0)
    {
        $tempSTR += $item
        $tempSTR += ','

        $count++
    }
}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

if($count -gt 0)
{
    $result = "취약"
    $CV = ("구동중인 IIS 서비스는 " + $tempSTR)
}
else
{
    $result = "양호"
    $CV = ("구동중인 IIS 서비스는 없습니다.")
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 11. 디렉토리 리스팅 제거 ###########

$index="11"
$title="디렉토리 리스팅 제거"

$RV = " 디렉토리 검색 옵션 해제"
$importance = "상"

$Site_List = Get-ChildItem IIS:\Sites | select -expand Name
$count = 0 

$tempSTR = @()

$PSPath = 'MACHINE/WEBROOT/APPHOST'
$Filter = 'system.webServer/directoryBrowse'
$Name = 'enabled'

foreach($Location in $Site_List)
{
    # 디렉토리 검색 허용 / 차단 설정한 값을 확인한다.
    $var = (Get-WebConfigurationProperty -PSPath $PSPath -Location $Location -Filter $Filter -Name $Name).Value

    if($var)
    {
        $tempSTR +=$Location
        $tempSTR += ','

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
    $CV = ("모든 사이트에서 디렉토리 검색 차단")
}
else
{
    $result = "취약"
    $CV = ($tempSTR + "사이트에서 디렉토리 검색 허용")    
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

######### 12. IIS CGI 실행 제한 양호 #########

$index="12"
$title="IIS CGI 실행 제한 양호"

$RV = "Everyone에 권한이 없는 경우"
$importance = "상"

$var = Test-Path -Path "C:\inetpub\scripts"

if(!$var)
{
    $result = "대상X"
    $CV = "CGI 디렉토리 존재 X"
}
else
{
    $access_info = Get-SmbShare | Where-Object {$_.Name -eq "script"} | Where-Object {$_.AccountName -like 'Everyone'}

    if($access_info.length -gt 0)
    {
        $result = "취약"
        $CV = "Everyone 권한이 존재"
    }
    else
    {
        $result = "양호"
        $CV = "Everyone 권한이 존재하지 않음"
        $access_info = Get-SmbShareAccess | Where-Object {$_.Name -eq "script"} | Format-wide
    }
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 13. IIS 상위 디렉토리 접근 금지 ###########

$index="13"
$title="IIS 상위 디렉토리 접근 금지"

$RV = "상위 패스 기능 제거"
$importance = "상"
$Site_List = Get-ChildItem IIS:\Sites | select -expand Name
$count = 0 

$tempSTR = @()

$PSPath = 'MACHINE/WEBROOT/APPHOST'
$Filter = 'system.webServer/asp'
$Name = 'enableParentPaths'

foreach($Location in $Site_List)
{
    # 부모 디렉토리 접근 허용 / 차단 설정한 값을 확인한다.
    $var = Get-WebConfigurationProperty -PSPath $PSPath -Location $Location -Filter $Filter -Name $Name | Select-Object Value | Format-Wide
    
    if($var)
    {
        $count++

        $tempSTR += $Location
        $tempSTR += ','

    }
}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

if($count -eq 0)
{
    $result = "양호"
    $CV = "모든 사이트가 상위 디렉토리 접근 금지가 적용"
}
else 
{
    $result = "취약"
    $CV = ($tempSTR + " 사이트가 상위 디렉토리 접근 적용")
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 14. IIS 불필요한 파일 제거 ###########

# IIS 7.0 (Windows 2008) 이상 버전 해당 없음

$index="14"
$title="IIS 불필요한 파일 제거"

$RV = "IISSamples, IIS Help 가상 디렉토리 제거"
$importance = "상"

if($IIS_version -lt 7)
{
    $CV = "수동 확인 후 존재 시 삭제"
    $result = "수동"
}
if($IIS_version -ge 7)
{
    $CV = "IIS 7이상은 해당X"
    $result = "대상X"
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 15. 웹 프로세스 권한 제한 ###########

$index="15"
$title="웹 프로세스 권한 제한"
$result = "수동"

$RV = "웹 서비스 운영에 필요한 최소 권한으로 설정"
$importance = "상"

$CV = @()

$String_1 = Get-content ./user_rights | Select-String "SeInteractiveLogonRight"
$String_1 = Out-String -InputObject $String_1

$String_1 = $String_1 -replace "`\s+",''

$String_2 = $String_1.Split("*,")
$SID_List = @()
$local_List = @()

for($X=1;$X -lt $String_2.count;$X++)
{
    if($String_2[$X].length -ne 0)
    {   
        if($String_2[$X] -like "S*")
        {
           $SID_List += $String_2[$X]
        }
        else
        {
            $local_List += $String_2[$X]
        }
    }
}

foreach($local_ITEM in $local_List)
{
    $CV += $local_ITEM.Trim()
    $CV += ','
}

foreach($SID_ITEM in $SID_List)
{
    $flag = Convert_SID_TO_USERNAME $SID_ITEM

    $flag = Out-String -InputObject $flag
    $flag = $flag.Split('\')
    $flag = $flag[-1].Trim()

    $CV += $flag
    $CV += ','
}

if($CV.count -gt 0)
{
    $CV[-1] = ''
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt


###############################################

########### 16. IIS 링크 사용 금지 ###########


$index="16"
$title="IIS 링크 사용 금지"
$importance = "상"

$RV = "바로가기(.lnk) 파일의 사용 허용X"

$total_web_count = 0
$total_lnk_count = 0
$tempSTR = @()

for($X=0;$X -lt $Site_Name_list.count;$X++)
{
    $lnk_count = (Get-ChildItem $Site_Path_list[$X] -Recurse | Where-Object {$_.Name -like "*.lnk"}).count

    if($lnk_count -gt 0)
    {
        $total_web_count++
        $total_lnk_count += $lnk_count

        $tempSTR += $Site_Name_list[$X]
        $tempSTR = ','
    }

}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

if($total_web_count -gt 0)
{
    $result = "취약"
    $CV = ("lnk파일 존재 사이트는 "+ $tempSTR +" 입니다.")
}
else
{
    $result = "양호"
    $CV = "모든 사이트에 lnk 파일이 존재하지 않습니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 17. IIS 파일 업로드 및 다운로드 제한 ###########

$index="17"
$title="IIS 파일 업로드 및 다운로드 제한"

$RV = "업로드 / 다운로드 용량을 제한"
$importance = "상"

$total_web_count = 0
$tempSTR = @()

for($X=0;$X -lt $Site_Name_list.count;$X++)
{
    # web.config 파일이 존재하는지 확인
    $flag = (Get-ChildItem $Site_Path_list[$X] | Where-Object {$_.Name -eq "web.config"}).count

    # web.config 파일이 존재하지 않을 때
    if($flag -eq 0)
    {
        $result = "취약"
        $total_web_count++
        $tempSTR += $Site_Name_list[$X]
        $tempSTR += ','
    }

    #web.config 파일이 정상적으로 홈 디렉토리에 1개가 존재하는 경우
    elseif($flag -eq 1)
    {
        #web.config 파일 경로 얻기
        $web_config_file_path = (Get-ChildItem $Site_Path_list[$X] | Where-Object {$_.Name -eq "web.config"}).Fullname
        
        #web.config 파일 내에서 파일 업로드 관련 설정이 있는지 확인
        $upload_option = Get-Content $web_config_file_path | Select-String -Pattern "maxAllowedContentLength"

        #web.config 파일 내에서 파일 다운로드 관련 설정이 있는지 확인
        $download_option = Get-Content $web_config_file_path | Select-String -Pattern "bufferingLimit"

        if($upload_option.length -le 0 -or $download_option.length -le 0)
        {
            $tempSTR += $Site_Name_list[$X]
            $tempSTR += ','
            $total_web_count++
        } 

    }

    #web.config 파일이 비 정상적으로 많이 생성 되었을 때 
    else
    {
        $result = "취약"
        $total_web_count++
        $tempSTR += $Site_Name_list[$X]
        $tempSTR += ','
    }

}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

if($total_web_count -gt 0)
{
    $result = "취약"
    $CV = ("업로드 혹은 다운로드 설정이 되지 않은 사이트는 " + $tempSTR +" 입니다.")
}
else 
{
    $result = "양호"
    $CV = ("모든 사이트가 업로드 / 다운로드 설정이 되어 있습니다.")
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 18. IIS DB 연결 취약점 점검 ###########

$index="18"
$title="IIS DB 연결 취약점 점검"

$RV = ".asa 매핑 시 특정 동작 설정 / .asa 매핑 존재X"
$importance = "상"

$IIS_Site_List = Get-IISSite | select-Object Name
$flag_asa = 0
$flag_asax = 0

$total_web_count = 0

$tempSTR = @()

for($X=0;$X -lt $Site_Name_list.count;$X++)
{
    #IIS 6.0 이하
    if($IIS_version -lt 7)
    {
        $flag_asa = (Get-WebHandler -PSPath $Site_Path_list[$X] | Where-Object {$_.Path -eq "*.asa"}).count
        if($flag_asa -eq 1)
        {
            $asa_verb = Get-WebHandler -PSPath $Site_Path_list[$X] | Where-Object {$_.Path -eq "*.asa"} | Select-Object Verb | Format-Wide     
            $asa_verb = String $asa_verb
            
            if($asa_verb -eq '*')
            {
                $total_web_count++

                $tempSTR += $Site_Name_list[$X]
                $tempSTR += ','

            }

        }

        $flag_asax = (Get-WebHandler -PSPath $Site_Path_list[$X] | Where-Object {$_.Path -eq "*.asax"}).count
        if($flag_asax -eq 1)
        {
            $asax_verb = Get-WebHandler -PSPath $Site_Path_list[$X] | Where-Object {$_.Path -eq "*.asax"} | Select-Object Verb | Format-Wide
            $asax_verb = String $asax_verb
            
            if($asax_verb -eq '*')
            {
                $total_web_count++

                $tempSTR += $Site_Name_list[$X]
                $tempSTR += ','

            }

        }

    }

    # IIS 7.0 이상
    elseif($IIS_version -ge 7)
    {
        $flag_asa = (Get-WebHandler -PSPath $Site_Path_list[$X] | Where-Object {$_.Path -eq "*.asa"}).count
        if($flag_asa -eq 1)
        {
            #echo($Site_Name + "사이트 처리기 매핑에 *.asa 매핑이 등록되어 있습니다. - 취약")
        }

        $flag_asax = (Get-WebHandler -PSPath $Site_Path_list[$X] | Where-Object {$_.Path -eq "*.asax"}).count
        if($flag_asax -eq 1)
        {
            #echo($Site_Name_list[$X] + "사이트 처리기 매핑에 *.asax 매핑이 등록되어 있습니다. - 취약")
        }

        if($flag_asa -eq 0 -and $flag_asax -eq 0)
        {
            #echo($Site_Name_list[$X] + "사이트는 처리기 매핑에 *asa , *.asax 매핑이 모두 등록되어 있지 않습니다. - 양호")
        }
        else
        {
            $total_web_count++
            $tempSTR += $Site_Name_list[$X]
            $tempSTR += ','    
        }
    }
}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

if($total_web_count -gt 0)
{
    $result = "취약"
    $CV = ($tempSTR + " 사이트에서 .asa 혹은 .asax 매핑 처리X")
}
else
{
    $result = "양호"
    $CV = ("모든 사이트에서 .asa 혹은 .asax 매핑 처리O")
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 19. IIS 가상 디렉토리 삭제 ###########


$index="19"
$title="IIS 가상 디렉토리 삭제"

$RV = "IIS Admin, IIS Adminpwd 가상 디렉토리 존재X"
$importance = "상"

$total_web_count = 0

$tempSTR = @()

# IIS 6.0 이상
if($IIS_version -ge 6)
{
    $CV = "IIS 6.0 버전 이상은 해당X"
    $result = "대상X"
}

# IIS 6.0 미만
elseif($IIS_version -lt 6)
{
    for($X=0;$X -lt $Site_Name_list.count;$X++)
    {
        $flag_admin = (Get-ChildItem $Site_Path_list[$X] | Where-Object {$_.Name -eq "IIS Admin"}).count
        if($flag_admin -gt 0)
        {
            #echo($Site_Name_list[$X] + "사이트에 IIS Admin 가상 디렉토리가 존재합니다. - 취약")
        }

        $flag_adpwd = (Get-ChildItem $Site_Path_list[$X] | Where-Object {$_.Name -eq "IIS Adminpwd"}).count
        if($flag_adpwd -gt 0)
        {
            #echo($Site_Name_list[$X] + "사이트에 IIS Adminpwd 가상 디렉토리가 존재합니다. - 취약")
        }

        if($flag_admin -eq 0 -and $flag_adpwd -eq 0)
        {
            #echo($Site_Name_list[$X] + "사이트에는 IIS Admin, IIS Adminpwd 가상 디렉토리가 존재하지 않습니다. - 양호")
        }
        else 
        {
            $tempSTR += $Site_Name_list[$X]
            $tempSTR += ','

            $total_web_count++   
        }

    }

    if($tempSTR.count -gt 0)
    {
        $tempSTR[-1] = ''
    }


    if($total_web_count -gt 0)
    {
        $CV = ($tempSTR + " 사이트에서 가상 디렉토리 발견")
        $result = "취약"
    }
    else
    {
        $CV = ("모든 사이트에서 가상 디렉토리 미발견")
        $result = "양호"
    }
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt


###############################################

########### 20. IIS 데이터 파일 ACL 적용 ###########


$index="20"
$title="IIS 데이터 파일 ACL 적용"

$RV = "홈 디렉토리 하위 모든파일에 Everyone 권한 존재X"
$importance = "상"
$total_web_count = 0

$tempSTR = @()

#$IIS_Site_List = Get-IISSite | select-Object Name
for($X=0;$X -lt $Site_Name_list.count;$X++)
{
    $Path_child_items = (Get-ChildItem -Path $Site_Path_list[$X] -Recurse).FullName
    $Everyone_Access_files_count = 0

    foreach($file_item in $Path_child_items)
    {
        $Everyone_Access_count = (Get-Permissions -Path $file_item | Where-Object {$_.IdentityReference -like "*Everyone*"}).Count
        
        if($Everyone_Access_count -gt 0)
        {
            #해당 사이트 Everyone 권한 허용 파일 갯수 증가
            $Everyone_Access_files_count++

        }
    }

    if($Everyone_Access_files_count -eq 0)
    {
        #echo($Site_Name_list[$X] + " 사이트 홈 디렉토리 내부에는 Everyone 권한을 가진 파일이 존재하지 않습니다. - 양호`n")
    }
    else
    {
        $tempSTR += $Site_Name_list[$X]
        $tempSTR += ','

        $total_web_count++
        #echo($Site_Name_list[$X] + " 사이트 홈 디렉토리에서는 " + "Everyone 권한을 가진 파일이 " + $Everyone_Access_files_count + "개 존재합니다. - 취약")
    }

}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}


if($total_web_count -gt 0)
{
    $CV = ("홈 디렉토리 하위 파일에 Everyone 권한이 존재하는 사이트는 " + $tempSTR + " 입니다.")
    $result = "취약"
}
else
{
    $CV = ("모든 사이트의 홈 디렉터리 하위 파일에 Everyone 권한 존재X")
    $result = "양호"
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt


###############################################

########### 21. IIS 미사용 스크립트 매핑 제거 ###########


$index="21"
$title="IIS 미사용 스크립트 매핑 제거"

$RV = "취약한 매핑 존재X"
$importance = "상"
$total_web_count = 0
$tempSTR = @()

$unsafe_mapping_list = @("*.htr*","*.idc*","*.stm*","*.shtm*","*.printer*","*.htw*","*.ida*","*.idq*")

for($X=0;$X -lt $Site_Name_list.count;$X++)
{
    $unsafe_mapping_count = 0

    foreach($mapping_item in $unsafe_mapping_list)
    {
        $flag = (Get-WebHandler -PSPath $Site_Path_list[$X] | Where-Object {$_.Path -like ($mapping_item)}).count

        if($flag -eq 1)
        {
            $unsafe_mapping_count++

            $mapping_item = $mapping_item.split('*')
            #echo($Site_Name_list[$X] + "사이트 처리기 매핑에 " + "*" + $mapping_item[1] +" 매핑이 등록되어 있습니다. - 취약")
        }
    }

    if($unsafe_mapping_count -eq 0)
    {
        #echo($Site_Name_list[$X] + " 사이트에서는 취약한 매핑이 존재하지 않습니다. - 양호`n")
    }
    else
    {
        $tempSTR += $Site_Name_list[$X]
        $tempSTR += ','

        $total_web_count++
        #echo($Site_Name_list[$X] + " 사이트에서는 총 " + $unsafe_mapping_count +"개의 취약한 매핑이 존재합니다. - 취약`n")
    }
   
}

if($tempSTR.count -gt 0)
{
    $tempSTR[-1] = ''
}

if($total_web_count -gt 0)
{
    $CV = ("취약한 매핑이 존재하는 사이트는 " + $tempSTR + " 입니다.")
    $result = "취약"
}
else
{
    $CV = ("모든 사이트에 취약한 매핑 존재X")
    $result = "양호"
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 22. IIS Exec 명령어 쉘 호출 진단 ###########

$index="22"
$title="IIS Exec 명령어 쉘 호출 진단"

$RV = "IIS 5미만 - REG값 0 / IIS 6이상"
$importance = "상"

# IIS 6.0 (Windows 2003) 이상 버전 해당 없음

if($IIS_version -lt 6)
{
    $CV = "수동 확인"
    $result = "수동"
}
elseif($IIS_version -ge 5)
{
    $CV = "해당 취약점은 IIS 6.0 이상은 해당되지 않습니다"
    $result = "대상X"
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################

########### 23. IIS WebDAV 비활성화 ###########

$index="23"
$title="IIS WebDAV 비활성화"

$RV = "IIS 서비스 미 사용 or DisableWebDAV 값 1"
$importance = "DisableWebDAV 경로 - HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"

$flag = (Get-WindowsFeature | Where-Object{$_.Name -eq "Web-Server"} | Where-Object{$_.Installed -eq "True"}).count

if($flag -eq 1)
{
    try{
    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters"
    $Name = "DisableWebDAV"

    $var = Get-ItemPropertyValue -Path $RegPath -Name $Name
    }
    catch
    {
        $result = "취약"
        $CV = "DisableWebDAV값 설정X"

    }
    if($var)
    {
        $result = "양호"
        $CV = "DisableWebDAV값 기능 사용"

    }
    elseif($var -eq 0)
    {
        $result = "취약"
        $CV = "DisableWebDAV 기능 미사용"

    }
}
else
{
    $result = "양호"
    $CV = "IIS 서비스 미사용"

}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt


###############################################

########### 24. NetBIOS 바인딩 서비스 구동 점검 ###########


$index="24"
$title="NetBIOS 바인딩 서비스 구동 점검"
$result = "수동"

$RV = "TCP/IP - NetBIOD 간의 바인딩 제거"
$importance = "상"

$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Netlogon\Parameters"
$Name = "AvoidFallbackNetbiosDiscovery"

$flag = Test-RegistryValue $RegPath $Name

if($flag)
{
    $var = Get-ItemPropertyValue -Path $RegPath -Name $Name

    if($var)
    {
        $CV = "바인딩이 제거 되어 있습니다."
        $result = "양호"
    }
    else
    {
        $CV = "바인딩이 제거 되어 있지 않습니다.."
        $result = "취약"
    }
}
else
{
    $CV = "기본값으로 설정"
    $result = "취약"  
}

# https://getadmx.com/?Category=Windows_10_2016&Policy=Microsoft.Policies.NetLogon::Netlogon_AvoidFallbackNetbiosDiscovery

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt


###############################################

########### 25. FTP 서비스 구동 점검 ###########


$index="25"
$title="FTP 서비스 구동 점검"

$RV = "FTP 사용X or secure FTP 사용"
$importance = "상"

$flag = (Get-Service | Where-Object {$_.Name -like "*Microsoft FTP Service*" -and $_.Status -eq "Running"}).Count

if($flag -gt 0)
{
    $result = "취약"
    $CV = "FTP 서비스를 사용 중 입니다."
}
else
{
    $result = "양호"
    $CV = "FTP 서비스를 사용하지 않습니다."
}

echo($index + "#" + $root_title + "#" + $title+"#" + $result) >> check_result.txt

echo($index + '#' + $root_title + '#' + $title + '#' + $RV + '#' + $CV + '#' + $result + '#' + $importance) >> check_result_more.txt

###############################################