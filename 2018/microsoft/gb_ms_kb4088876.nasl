###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4088876.nasl 9478 2018-04-13 13:28:27Z cfischer $
#
# Microsoft Windows Multiple Vulnerabilities (KB4088876)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812827");
  script_version("$Revision: 9478 $");
  script_cve_id("CVE-2018-0811", "CVE-2018-0813", "CVE-2018-0814", "CVE-2018-0886", 
                "CVE-2018-0888", "CVE-2018-0889", "CVE-2018-0891", "CVE-2018-0894", 
                "CVE-2018-0895", "CVE-2018-0896", "CVE-2018-0897", "CVE-2018-0898", 
                "CVE-2018-0899", "CVE-2018-0900", "CVE-2018-0901", "CVE-2018-0904", 
                "CVE-2018-0927", "CVE-2018-0929", "CVE-2018-0932", "CVE-2018-0935", 
                "CVE-2018-0942", "CVE-2018-0816", "CVE-2018-0817", "CVE-2018-0868", 
                "CVE-2018-0878", "CVE-2018-0881", "CVE-2018-0883", "CVE-2018-0885");
  script_bugtraq_id(103232, 103250, 103251, 103265, 103262, 103295, 103309, 103231,
                    103238, 103240, 103241, 103242, 103243, 103244, 103245, 103246,
                    103310, 103299, 103307, 103298, 103312, 103248, 103249, 103236,
                    103230, 103256, 103259, 103261);  
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-13 15:28:27 +0200 (Fri, 13 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-14 09:46:08 +0530 (Wed, 14 Mar 2018)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4088876)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4088876");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaw exists due to,
  
  - When Windows Hyper-V on a host operating system fails to properly validate 
    input from an authenticated user on a guest operating system. 

  - The way that the scripting engine handles objects in memory in Internet 
    Explorer. 

  - When Microsoft Hyper-V Network Switch on a host server fails to properly 
    validate input from a privileged user on a guest operating system. 

  - The Credential Security Support Provider protocol (CredSSP). 

  - When the Microsoft Video Control mishandles objects in memory. 

  - When Windows Shell does not properly validate file copy destinations. 

  - When Internet Explorer improperly handles objects in memory. 

  - When Internet Explorer fails a check, allowing sandbox escape. 

  - The Windows kernel that could allow an attacker to retrieve information 
    that could lead to a Kernel Address Space Layout Randomization (ASLR) bypass. 

  - The Windows Installer when the Windows Installer fails to properly sanitize 
    input leading to an insecure library loading behavior.  

  - The Windows kernel improperly initializes objects in memory. 

  - When Windows Remote Assistance incorrectly processes XML External Entities 
    (XXE). 

  - The way that the Windows Graphics Device Interface (GDI) handles objects in 
    memory. ");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker
  to gain access to information, crash server and run arbitrary code in system
  mode.

  Impact Level: System");

  script_tag(name:"affected", value:"Microsoft Windows 8.1 for 32-bit/x64

  Microsoft Windows Server 2012 R2");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/4088876");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4088876");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = "";
fileVer = "";

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

fileVer = fetch_file_version(sysPath, file_name:"urlmon.dll");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"11.0.9600.18939"))
{
  report = report_fixed_ver(file_checked:sysPath + "\urlmon.dll",
  file_version:fileVer, vulnerable_range:"Less than 11.0.9600.18939");
  security_message(data:report);
  exit(0);
}
exit(0);
