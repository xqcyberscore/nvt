###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-028.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Internet Explorer Multiple Use After Free Vulnerabilities (2817183)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary HTML or
  script code in the context of the current user.
  Impact Level: Application";

tag_affected = "Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x";
tag_insight = "Unspecified use-after-free error occurs when dereference already freed
  memory.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-028";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS13-028.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903305");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1303", "CVE-2013-1304", "CVE-2013-1338");
  script_bugtraq_id(58850, 58851, 59633);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-04-10 08:12:20 +0530 (Wed, 10 Apr 2013)");
  script_name("Microsoft Internet Explorer Multiple Use After Free Vulnerabilities (2817183)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52874");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-028");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
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

## Variables Initialization
sysPath = "";
ieVer   = "";
dllVer  = NULL;

## Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2, win8:1) <= 0){
  exit(0);
}

## Get IE Version from KB
ieVer = get_kb_item("MS/IE/Version");
if(!ieVer || !(ieVer =~ "^(6|7|8|9|10)")){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Mshtml.dll
dllVer = fetch_file_version(sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  ## Check for Mshtml.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.2900.6357") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.17127")||
     version_in_range(version:dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21329")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19411")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23479")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5128") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.17127")||
     version_in_range(version:dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21329")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19411")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23479")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18793")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23063")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19411")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23479")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16475")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20585")){
    security_message(0);
  }
  exit(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.17266")||
     version_in_range(version:dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.21483")||
     version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.18105")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.22271")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16475")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20585")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16539")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20643")){
    security_message(0);
  }
  exit(0);
}

## Windows 8
else if(hotfix_check_sp(win8:1) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16539")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20643")){
    security_message(0);
  }
  exit(0);
}
