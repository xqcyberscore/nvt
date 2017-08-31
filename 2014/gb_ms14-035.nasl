###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-035.nasl 6715 2017-07-13 09:57:40Z teissa $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (2969262)
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
  script_oid("1.3.6.1.4.1.25623.1.0.804595");
  script_version("$Revision: 6715 $");
  script_cve_id("CVE-2014-0282", "CVE-2014-1762", "CVE-2014-1764", "CVE-2014-1766",
                "CVE-2014-1769", "CVE-2014-1770", "CVE-2014-1771", "CVE-2014-1772",
                "CVE-2014-1773", "CVE-2014-1774", "CVE-2014-1775", "CVE-2014-1777",
                "CVE-2014-1778", "CVE-2014-1779", "CVE-2014-1780", "CVE-2014-1781",
                "CVE-2014-1782", "CVE-2014-1783", "CVE-2014-1784", "CVE-2014-1785",
                "CVE-2014-1786", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790",
                "CVE-2014-1791", "CVE-2014-1792", "CVE-2014-1794", "CVE-2014-1795",
                "CVE-2014-1796", "CVE-2014-1797", "CVE-2014-1799", "CVE-2014-1800",
                "CVE-2014-1802", "CVE-2014-1803", "CVE-2014-1804", "CVE-2014-1805",
                "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2756",
                "CVE-2014-2757", "CVE-2014-2758", "CVE-2014-2759", "CVE-2014-2760",
                "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2765",
                "CVE-2014-2766", "CVE-2014-2767", "CVE-2014-2768", "CVE-2014-2769",
                "CVE-2014-2770", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2773",
                "CVE-2014-2775", "CVE-2014-2776", "CVE-2014-2777");
  script_bugtraq_id(67862, 67511, 67295, 67518, 67863, 67544, 67861, 67864,
                    67866, 67867, 67871, 67869, 67882, 67872, 67873, 67874,
                    67875, 67876, 67877, 67878, 67879, 67880, 67881, 67883,
                    67884, 67885, 67886, 67887, 67889, 67890, 67891, 67831,
                    67833, 67834, 67835, 67836, 67838, 67839, 67840, 67841,
                    67842, 67843, 67845, 67846, 67847, 67915, 67848, 67849,
                    67850, 67851, 67852, 67854, 67855, 67856, 67857, 67858,
                    67859, 67860, 67892);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-07-13 11:57:40 +0200 (Thu, 13 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-11 08:05:23 +0530 (Wed, 11 Jun 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2969262)");

  tag_summary =
"This host is missing a critical security update according to Microsoft
Bulletin MS14-035.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Multiple flaws are due to,
- A use-after-free error when handling CMarkup objects.
- An error when handling negotiation of certificates during a TLS session.
- Improper validation of certain permissions.
- and multiple Unspecified errors.";

  tag_impact =
"Successful exploitation will allow attackers to conduct session hijacking
attacks, disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system.

Impact Level: System/Application";

  tag_affected =
"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x/11.x";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-035";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/58768");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2957689");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2963950");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/ms14-035");
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
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2, win8:1,
                   win8x64:1, win2012:1, win8_1:1, win8_1x64:1) <= 0){
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
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5341") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21388")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23597")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19097")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23388")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19538")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23597")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16554")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20665")){
    security_message(0);
  }
  exit(0);
}

## Windows 7 and Server 2008r2
else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.18471")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.22685")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16554")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20665")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16920")||
     version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21043")||
     version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.16667")||
     version_in_range(version:dllVer, test_version:"11.0.9600.17000", test_version2:"11.0.9600.17125")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and Server 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16920")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21043")){
    security_message(0);
  }
  exit(0);
}

## Windows 8.1
else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.16667")||
     version_in_range(version:dllVer, test_version:"11.0.9600.17000", test_version2:"11.0.9600.17125")){
    security_message(0);
  }
  exit(0);
}
