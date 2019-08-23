# 압축 풀기.
function Extract-Zip
{
  param([string]$zipfilename, [string] $destination=".") #목적지 기본값은 현재 디렉토리

  #상대경로를 절대경로로 변경
  $zipfilename = (Get-Item $zipfilename).FullName
  $destination = (Get-Item $destination).FullName

  if(test-path($zipfilename))
  {  
    $shellApplication = new-object -com shell.application
    $zipPackage = $shellApplication.NameSpace($zipfilename)
    $destinationFolder = $shellApplication.NameSpace($destination)
    $destinationFolder.CopyHere($zipPackage.Items())
  }
}

# 양식 압축 파일을 복사하여 가져오기
Copy-Item -Path ".\Document_Form\check_document_form.docx" -Destination $args[0]

Rename-Item -Path ($args[0] + "\check_document_form.docx") ($args[0] + "\check_document_form.docx.zip")

#create temp dir
mkdir ($args[0] + "\temp") | Out-Null
Extract-Zip -zipfilename ($args[0] + "\check_document_form.docx.zip") -destination ($args[0] + "\temp")

# replace text
$bodyFile = $args[0] + "\temp" + "\word\document.xml"
$body = Get-Content $bodyFile -Encoding UTF8

$txt = $args[0] + "\check_result_more.txt"
$basic_txt = $args[0] + "\server_basic_info.txt"

$result_count = @(0,0,4,0)     #양호 , 취약 , 수동 , 대상X
$importance_count = @(0,0,0)
$category_count=@(0,0,0,0)

$total_category = 0
$total_importance = 0
$total_result = 0

foreach($line in Get-Content $txt)
{
    $line = $line.Split('#')

    if($line[5] -eq "취약")
    {
        $result_count[1]++

        switch($line[6])
        {
            "상"{$importance_count[0]++;break}
            "중"{$importance_count[1]++;break}
            "하"{$importance_count[2]++;break}
        }

        switch($line[1])
        {
            "계정 관리"{$category_count[0]++;break}
            "서비스 관리"{$category_count[1]++;break}
            "로그 관리"{$category_count[2]++;break}
            "보안 관리"{$category_count[3]++;break}
        }
    }
    elseif($line[5] -eq "양호")
    {
        $result_count[0]++
    }
        elseif($line[5] -eq "수동")
    {
        $result_count[2]++
    }
        elseif($line[5] -eq "대상X")
    {
        $result_count[3]++
    }

    #result
    $result_str = "result" + $line[0]
    $body = $body -replace $result_str,$line[5]

    #Current Value
    $CV = "CV" + $line[0]
    $body = $body -replace $CV,$line[4]

}

# input basic information 
$ver = Get-Content $basic_txt

$body = $body -replace "basicinfo1",$args[1]
$body = $body -replace "basicinfo2",$ver

$Date = $args[2].split('_')

$body = $body -replace "basicinfo3",($Date[0] + "년 " + $Date[1] + "월 " + $Date[2] + "일 " + $Date[3] + "시 " + $Date[4] + "분")

# input total result
$body = $body -replace "resultgood",$result_count[0].ToString()
$body = $body -replace "resultdanger",$result_count[1].ToString()
$body = $body -replace "resultmanual",$result_count[2].ToString()
$body = $body -replace "resultnot",$result_count[3].ToString()
$body = $body -replace "resultall",($result_count[0]+$result_count[1]+$result_count[2]+$result_count[3]).ToString()

$body = $body -replace "resulthigh",$importance_count[0].ToString()
$body = $body -replace "resultmedium",$importance_count[1].ToString()
$body = $body -replace "resultlow",$importance_count[2].ToString()
$body = $body -replace "resulttotal",($importance_count[0]+$importance_count[1]+$importance_count[2]).ToString()

$body = $body -replace "resultA",$category_count[0].ToString()
$body = $body -replace "resultB",$category_count[1].ToString()
$body = $body -replace "resultC",'0'
$body = $body -replace "resultD",$category_count[2].ToString()
$body = $body -replace "resultE",$category_count[3].ToString()
$body = $body -replace "resultF",'0'
$body = $body -replace "resultT",($category_count[0]+$category_count[1]+$category_count[2]+$category_count[3]).ToString()

# save new xml file
$Utf8NoBomEncoding = New-Object System.Text.UTF8Encoding($False)
[System.IO.File]::WriteAllLines($bodyFile, $body, $Utf8NoBomEncoding)