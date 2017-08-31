###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-031.nasl 6663 2017-07-11 09:58:05Z teissa $
#
# Microsoft Windows TCP Protocol Denial of Service Vulnerability (2962478)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804636");
  script_version("$Revision: 6663 $");
  script_cve_id("CVE-2014-1811");
  script_bugtraq_id(67888);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-11 11:58:05 +0200 (Tue, 11 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-11 12:45:39 +0530 (Wed, 11 Jun 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Windows TCP Protocol Denial of Service Vulnerability (2962478)");

   tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS14-031.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw is due to some error within the Windows TCP/IP networking protocol which
allows processing of crafted packets.";

  tag_impact =
"Successful exploitation will allow attackers to cause denial of service
condition.";

  tag_affected =
"Microsoft Windows 8 x32/x64
Microsoft Windows 8.1 x32/x64
Microsoft Windows Server 2012
Microsoft Windows Server 2012 R2
Microsoft Windows 7 x32/x64 Service Pack 1 and prior
Microsoft Windows Vista x32/x64 Service Pack 2 and prior
Microsoft Windows Server 2008 x32/x64 Service Pack 2 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/library/security/ms14-031";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/ms14-031");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2957189");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2961858");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, winVistax64:3, win7:2, win7x64:2, win2008:3,
                   win2008x64:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from tcpip.sys file
sysVer = fetch_file_version(sysPath, file_name:"system32\drivers\tcpip.sys");
if(!sysVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for tcpip.sys version
  if(version_in_range(version:sysVer, test_version:"6.0.6002.18000", test_version2:"6.0.6002.19079") ||
     version_in_range(version:sysVer, test_version:"6.0.6002.23000", test_version2:"6.0.6002.23369")){
    security_message(0);
  }
  exit(0);
}


## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for tcpip.sys version
  if(version_in_range(version:sysVer, test_version:"6.1.7601.18000", test_version2:"6.1.7601.18437") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22647")){
    security_message(0);
  }
}

else if(hotfix_check_sp(win8:1,  win8x64:1, win2012:1) > 0)
{
  ## Check for tcpip.sys version
  if(version_in_range(version:sysVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16885") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21004")){
    security_message(0);
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
  ## Check for tcpip.sys version
  if(version_in_range(version:sysVer, test_version:"6.3.9600.16000", test_version2:"6.3.9600.16659") ||
     version_in_range(version:sysVer, test_version:"6.3.9600.17000", test_version2:"6.3.9600.17087")){
    security_message(0);
  }
  exit(0);
}
