###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-037.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (2975687)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804713");
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-2783", "CVE-2014-1763", "CVE-2014-1765", "CVE-2014-2785",
                "CVE-2014-2786", "CVE-2014-2787", "CVE-2014-2788", "CVE-2014-2789",
                "CVE-2014-2790", "CVE-2014-2791", "CVE-2014-2792", "CVE-2014-2794",
                "CVE-2014-2795", "CVE-2014-2797", "CVE-2014-2798", "CVE-2014-2800",
                "CVE-2014-2801", "CVE-2014-2802", "CVE-2014-2803", "CVE-2014-2804",
                "CVE-2014-2806", "CVE-2014-2807", "CVE-2014-2809", "CVE-2014-2813");
  script_bugtraq_id(68391, 66200, 66244, 68369, 68371, 68372, 68373, 68374,
                    68375, 68376, 68377, 68378, 68379, 68380, 68381, 68382,
                    68383, 68384, 68385, 68386, 68387, 68388, 68389, 68390);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-07-09 10:07:32 +0530 (Wed, 09 Jul 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2975687)");

  tag_summary =
"This host is missing a critical security update according to Microsoft
Bulletin MS14-037.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to,
- An error when handling EV (Extended Validation) SSL certificates.
- and multiple Unspecified errors.";

  tag_impact =
"Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system.

Impact Level: System/Application";

  tag_affected =
"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x/11.x";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-037";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/59775");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2962872");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2963952");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2975687");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/ms14-037");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
ieVer   = "";
dllVer  = NULL;

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8x64:1, win2012:1,
                   win2012R2:1, win8_1:1, win8_1x64:1) <= 0){
  exit(0);
}

## Get IE Version
ieVer = get_app_version(cpe:CPE);
if(!ieVer || !(ieVer =~ "^(6|7|8|9|10|11)")){
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

## Windows 2003
if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5358") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21394")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23602")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19113")||
     version_in_range(version:dllVer, test_version:"7.0.6002.23000", test_version2:"7.0.6002.23412")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19542")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23602")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16560")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20671")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Server 2008r2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"8.0.7601.18000", test_version2:"8.0.7601.18486")||
     version_in_range(version:dllVer, test_version:"8.0.7601.22000", test_version2:"8.0.7601.22702")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16560")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20671")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17027")||
     version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21144")||
     version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.16671")||
     version_in_range(version:dllVer, test_version:"11.0.9600.17000", test_version2:"11.0.9600.17206")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and Server 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.17027")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21144")){
    security_message(0);
  }
  exit(0);
}

## Windows 8.1 and Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.16671")||
     version_in_range(version:dllVer, test_version:"11.0.9600.17000", test_version2:"11.0.9600.17206")){
    security_message(0);
  }
  exit(0);
}
