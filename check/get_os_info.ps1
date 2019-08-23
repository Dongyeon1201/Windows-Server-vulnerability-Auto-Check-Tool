$Buildnum = ([Environment]::OSVersion).Version.Build

switch($Buildnum)
{
    16299
    {
        $OS = "Windows Server 2017"
    }
    14393
    {
        $OS = "Windows Server 2016"
    }
    9600
    {
        $OS = "Windows Server 2012 R2"
    }
    9200
    {
        $OS = "Windows Server 2012"
    }
    7601
    {
        $OS = "Windows Server 2012 R2 SP1"
    }
    7600
    {
        $OS = "Windows Server 2012 R2"
    }
    6002
    {
        $OS = "Windows Server 2012 SP2"
    }
    6001
    {
        $OS = "Windows Server 2012 SP1"
    }
}

$OS > server_basic_info.txt
