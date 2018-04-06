###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-077.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (2761465)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  code in the context of the user.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 6.x/7.x/8.x/9.x";
tag_insight = "Multiple vulnerabilities are due to use-after-free errors within the
  'InjectHTMLStream()' function, 'CMarkup' class and 'Ref Counting'.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-077";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-077.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902696");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-4781", "CVE-2012-4782", "CVE-2012-4787");
  script_bugtraq_id(56828, 56829, 56830);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-12-12 10:17:14 +0530 (Wed, 12 Dec 2012)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2761465)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_keys("MS/IE/Version");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51411/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2761465");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027851");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-077");
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
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
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
  if(version_is_less(version:dllVer, test_version:"6.0.2900.6315") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.17115")||
     version_in_range(version:dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21317")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19392")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23460")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5080") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.17115")||
     version_in_range(version:dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21317")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19392")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23460")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18726")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22970")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19392")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23460")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16456")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20564")){
    security_message(0);
  }
  exit(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.17165")||
     version_in_range(version:dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.21368")||
     version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.17997")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.22159")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16456")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20564")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16438")){
    security_message(0);
  }
}
