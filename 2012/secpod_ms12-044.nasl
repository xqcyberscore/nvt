###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-044.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (2719177)
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

tag_impact = "Successful exploitation could allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the current user.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 9.x";
tag_insight = "Multiple vulnerabilities are due to the way that Internet Explorer
  accesses an object that has been deleted.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-044";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-044.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902686");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1522", "CVE-2012-1524");
  script_bugtraq_id(54293, 54294);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-07-11 09:42:59 +0530 (Wed, 11 Jul 2012)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2719177)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45690");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2719177");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027226");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-044");

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
## Windows Vista ,Windows Server 2008 and Windows 7
if(hotfix_check_sp(winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## Get IE Version from KB
ieVer = get_kb_item("MS/IE/Version");
if(!ieVer || !(ieVer =~ "^9")){
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

## Check for Mshtml.dll version less than 9.0.8112.16447 or 9.0.8112.20553
if(version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16446")||
   version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20552")){
   security_message(0);
}
