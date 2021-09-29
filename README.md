# Windows-Server-vulnerability-Auto-Check-Tool

This program is a tool that allows you to automatically check for vulnerabilities in your Windows server and verify the diagnostics results with a PDF report.

The vulnerability has been applied to KISA's document

PDF LINK : https://www.kisa.or.kr/public/laws/laws3_View.jsp?cPage=6&mode=view&p_No=259&b_No=259&d_No=106&ST=T&SV=

Diagnostics available: Windows Server 2012~
Tools Runable OS: Windows

Vulnerability Check Script : Powershell 5.1.1
GUI: Python 3.6.6

* Usage
 
1-1 . Setting up a check server
1. Apply Enable-PSRemoting -Force command
2. Allow port 5985,5986

1-2 . Setting up check tool execution client
1 . Get-Item WSMan:\localhost\Client\TrustedHosts
2 . Set-Item WSMan:\localhost\Client\TrustedHosts -Value *

2. Set Main.py and other folders to the same path, then run the Main.py file.

3. Set all options for administrator account information / check result report storage location / check result PDF encryption for stable check script execution.

Demonstration Video LINK (Youtube) : https://youtu.be/3fxq0EwZGTU

<hr></hr>

이 프로그램은 윈도우 서버의 취약점을 자동으로 점검 후 진단 결과를 PDF 보고서로 확인할 수 있도록 하는 도구 입니다.

취약점은 KISA의 '주요 정보통신 기반 시설_2017.PDF' 문서를 적용하였습니다.

PDF LINK : https://www.kisa.or.kr/public/laws/laws3_View.jsp?cPage=6&mode=view&p_No=259&b_No=259&d_No=106&ST=T&SV=

진단 가능 서버 : Windows Server 2012 ~
도구 실행 가능 OS : Windows

취약점 점검 스크립트 : Powershell 5.1.1
GUI : Python 3.6.6

* 사용법
 
1-1 . 점검 서버 설정
1. Enable-PSRemoting -Force 명령어 적용
2. 5985,5986 포트 허용

1-2 . 점검 도구 실행 클라이언트 설정
1 . Get-Item WSMan:\localhost\Client\TrustedHosts
2 . Set-Item WSMan:\localhost\Client\TrustedHosts -Value *

2. Main.py와 다른 폴더들을 같은 경로로 설정한 후, Main.py 파일을 실행한다.

3 . 안정적인 점검 스크립트 실행을 위해 관리자 계정 정보 / 점검 결과 보고서 저장 위치 / 점검 결과 PDF 암호화 여부 옵션을 모두 설정합니다.

시연 동영상 유튜브 : https://youtu.be/3fxq0EwZGTU
