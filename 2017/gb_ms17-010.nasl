###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms17-010.nasl 6225 2017-05-26 19:21:16Z cfi $
#
# Microsoft Windows SMB Server Multiple Vulnerabilities (4013389) 
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810810");
  script_version("$Revision: 6225 $");
  script_cve_id("CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146",
                "CVE-2017-0147", "CVE-2017-0148");
  script_bugtraq_id(96703, 96704, 96705, 96707, 96709, 96706);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-26 21:21:16 +0200 (Fri, 26 May 2017) $");
  script_tag(name:"creation_date", value:"2017-03-15 09:07:19 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows SMB Server Multiple Vulnerabilities (4013389)");

  script_tag(name:"summary", value:"This host is missing an critical security
  update according to Microsoft Bulletin MS17-010(WannaCrypt)");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws exist due to the way that the
  Microsoft Server Message Block 1.0 (SMBv1) server handles certain
  requests(WannaCrypt).");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to  gain the ability to execute code on the target server, also could
  lead to information disclosure from the server.

  Impact Level: System");
  script_tag(name:"affected", value:"
  Microsoft Windows 2003 x32/x64 Edition Service Pack 2 and prior

  Microsoft Windows XP SP2 x64

  Microsoft Windows XP SP3 x86

  Microsoft Windows 8 x86/x64

  Microsoft Windows 10 x32/x64 Edition

  Microsoft Windows Server 2012 Edition

  Microsoft Windows Server 2016

  Microsoft Windows 8.1 x32/x64 Edition

  Microsoft Windows Server 2012 R2 Edition

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Vista x32/x64 Edition Service Pack 2

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS17-010
  http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-in/kb/4013078");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS17-010");
  script_xref(name : "URL" , value : "http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598");
  script_xref(name : "URL" , value : "https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
sysVer = "";

## Check for OS and Service Pack
## Windows XP, server2003 and windows 8 support given due to the dispute over WannaCry Ransomware.
if(hotfix_check_sp(xp:4, xpx64:3, win2003:3, win2003x64:3, win8:1, win8x64:1,
                   winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   winVistax64:3, win2008x64:3, win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win10:1, win10x64:1, win2016:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

##Fetch the version of files
vistVer = fetch_file_version(sysPath, file_name:"drivers\srv.sys");
if(vistVer)
{
  ## Windows Vista and Server 2008
  if(hotfix_check_sp(winVista:3, winVistax64:3, win2008:3, win2008x64:3) > 0)
  {
    ## Check for srv.sys version
    if(version_is_less(version:vistVer, test_version:"6.0.6002.19743"))
    {
      Vulnerable_range1 = "Less than 6.0.6002.19743";
      VULN1 = TRUE ;
    }

    else if(version_in_range(version:vistVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.24066"))
    {
      Vulnerable_range1 = "6.0.6002.22000 - 6.0.6002.24066";
      VULN1 = TRUE ;
    }
  }
 
  ## Windows XP
  ## http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598
  else if(hotfix_check_sp(xp:4) > 0)
  {
    ## Check for srv.sys version, on 32bit xp sp3
    if(version_is_less(version:vistVer, test_version:"5.1.2600.7208"))
    {
      Vulnerable_range1 = "Less than 5.1.2600.7208";
      VULN1 = TRUE ;
    }
  }

  ## Windows 2003, Windows XP SP2 64bit
  ## http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598
  else if(hotfix_check_sp(win2003:3, win2003x64:3, xpx64:3) > 0)
  {
    if(version_is_less(version:vistVer, test_version:"5.2.3790.6021"))
    {
      Vulnerable_range1 = "Less than 5.2.3790.6021";
      VULN1 = TRUE ;
    }
  }

  ## Windows 8
  ## http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598
  else if(hotfix_check_sp(win8:1, win8x64:1) > 0)
  {
    if(version_is_less(version:vistVer, test_version:"6.2.9200.22099"))
    {
      Vulnerable_range1 = "Less than 6.2.9200.22099";
      VULN1 = TRUE ;
    }
  }
  
  if(VULN1)
  {
    report = 'File checked:     ' + sysPath + "\drivers\srv.sys" + '\n' +
             'File version:     ' + vistVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range1 + '\n' ;
    security_message(data:report);
    exit(0);
  }
}

winVer  = fetch_file_version(sysPath, file_name:"Win32k.sys");
if(winVer)
{
  ## Windows 7 and Windows Server 2008 R2
  if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0 && winVer)
  {
    if(version_is_less(version:winVer, test_version:"6.1.7601.23677"))
    {
      Vulnerable_range = "Less than 6.1.7601.23677";
      VULN = TRUE ;
   }
  }

  ## Windows Server 2012
  else if(hotfix_check_sp(win2012:1) > 0)
  {
    ## Check for win32k.sys version
    if(version_is_less(version:winVer, test_version:"6.2.9200.22097"))
    {
      Vulnerable_range = "Less than 6.2.9200.22097";
      VULN = TRUE ;
    }
  }

  ## Windows 8.1 and Server 2012 R2
  else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
  {
    ## Check for win32k.sys version
    if(version_is_less(version:winVer, test_version:"6.3.9600.18603"))
    {
      Vulnerable_range = "Less than 6.3.9600.18603";
      VULN = TRUE ;
    }
  }

  if(VULN)
  {
     report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
              'File version:     ' + winVer  + '\n' +
              'Vulnerable range: ' + Vulnerable_range + '\n' ;
     security_message(data:report);
     exit(0);
  }
}

##Fetch the version of 'Edgehtml.dll'
edgeVer = fetch_file_version(sysPath, file_name:"Edgehtml.dll");
if(!edgeVer){
  exit(0);
}

##Windows 10
if(hotfix_check_sp(win10:1, win10x64:1, win2016:1) > 0)
{
  ## Check for Edgehtml.dll version
  if(version_is_less(version:edgeVer, test_version:"11.0.10240.17319"))
  {
    Vulnerable_range = "Less than 11.0.10240.17319";
    VULN = TRUE ;
  }

  ## Windows 10 Version 1511
  else if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.838"))
  {
    Vulnerable_range = "11.0.10586.0 - 11.0.10586.838";
    VULN = TRUE ;
  }

  ## Windows 10 version 1607 and Windows Server 2016
  else if(version_in_range(version:edgeVer, test_version:"11.0.14393.0", test_version2:"11.0.14393.952"))
  {
    Vulnerable_range = "11.0.14393.0 - 11.0.14393.952";
    VULN = TRUE ;
  }

  if(VULN)
  {
    report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
             'File version:     ' + edgeVer  + '\n' +
             'Vulnerable range: ' + Vulnerable_range + '\n' ;
    security_message(data:report);
    exit(0);
  }
}
