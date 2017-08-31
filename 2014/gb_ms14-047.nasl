###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-047.nasl 6735 2017-07-17 09:56:49Z teissa $
#
# Microsoft Windows RPC Security Feature Bypass Vulnerability (2978668)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802078");
  script_version("$Revision: 6735 $");
  script_cve_id("CVE-2014-0316");
  script_bugtraq_id(69097);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-17 11:56:49 +0200 (Mon, 17 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-08-13 08:52:09 +0530 (Wed, 13 Aug 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Windows RPC Security Feature Bypass Vulnerability (2978668)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS14-047";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to RPC improperly frees messages that the server rejects as
malformed, allowing an attacker to fill up the address space of a process.";

  tag_impact =
"Successful exploitation will allow remote attackers to bypass the ASLR
security feature in conjunction with another vulnerability.

Impact Level: System";

  tag_affected =
"Microsoft Windows 8 x32/x64 Edition
Windows 8.1 x32/x64 Edition
Microsoft Windows Server 2012/R2
Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/library/security/MS14-047";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2978668");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS14-047");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");


## Variables Initialization
sysPath = "";
Rpcrt4Ver="";

## Check for OS and Service Pack
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8:1,
                   win8x64:1, win8_1:1, win8_1x64:1, win2012:1,
                   win2012R2:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

Rpcrt4Ver = fetch_file_version(sysPath, file_name:"system32\Rpcrt4.dll");
if(!Rpcrt4Ver){
  exit(0);
}

## Windows 7 and Windows Server 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Rpcrt4.dll version
  if(version_is_less(version:Rpcrt4Ver, test_version:"6.1.7601.18532") ||
     version_in_range(version:Rpcrt4Ver, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22742")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and Windows Server 2012
else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  ## Check for Rpcrt4.dll version
  if(version_is_less(version:Rpcrt4Ver, test_version:"6.2.9200.17037") ||
     version_in_range(version:Rpcrt4Ver, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21153")){
   security_message(0);
  }
  exit(0);
}

## Win 8.1 and Win 2012 R2
if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Rpcrt4.dll version
  if(version_is_less(version:Rpcrt4Ver, test_version:"6.3.9600.17216")){
    security_message(0);
  }
  exit(0);
}
