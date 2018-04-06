###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-006.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Windows Security Feature Bypass Vulnerability (2785220)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to silently downgrade
  a SSL version 3 or TLS connection to SSL version 2, which supports weak
  encryption cyphers.
  Impact Level: System";

tag_affected = "Microsoft Windows 7 x32/x64 Edition Service Pack 1 and prior
  Microsoft Windows Vista x32/x64 Edition Service Pack 2 and prior
  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
  Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2 and prior";
tag_insight = "The vulnerability is caused when Windows fails to properly handle SSL/TLS
  session version negotiation.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  https://technet.microsoft.com/en-us/security/bulletin/ms13-006";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-006.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901214");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-0013");
  script_bugtraq_id(57144);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-09 12:04:09 +0530 (Wed, 09 Jan 2013)");
  script_name("Microsoft Windows Security Feature Bypass Vulnerability (2785220)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51724");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2785220");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-006");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
sysPath = "";
exeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Ncrypt.dll file
exeVer = fetch_file_version(sysPath, file_name:"system32\Ncrypt.dll");
if(!exeVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
## Currently not supporting for Vista and Windows Server 2008 64 bit
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Ncrypt.dll version
  if(version_is_less(version:exeVer, test_version:"6.0.6002.18736") ||
     version_in_range(version:exeVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22980")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Windows 2008 R2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Ncrypt.dll version
  if(version_is_less(version:exeVer, test_version:"6.1.7600.17172") ||
     version_in_range(version:exeVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21376")||
     version_in_range(version:exeVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.18006")||
     version_in_range(version:exeVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22168")){
    security_message(0);
  }
}
