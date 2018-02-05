###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-037.nasl 8649 2018-02-03 12:16:43Z teissa $
#
# Microsoft Internet Explorer Multiple Vulnerabilities (2699988)
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
  information or execute arbitrary code in the context of the application.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Explorer version 6.x/7.x/8.x/9.x";
tag_insight = "Multiple vulnerabilities are due to the way that Internet Explorer,
  - Handles content using specific strings when sanitizing HTML.
  - Handles EUC-JP character encoding.
  - Processes NULL bytes, which allows to disclose content from the process
    memory.
  - Accesses an object that has been deleted, which allows to corrupt memory
    using Internet Explorer Developer Toolbar.
  - Accesses an object that does not exist, when handling the 'Col' element.
  - Accesses an object that has been deleted, when handling Same ID Property,
   'Title' element, 'OnBeforeDeactivate' event, 'insertRow' method and
   'OnRowsInserted' event allows to corrupt memory.
  - Accesses an undefined memory location, when handling the
   'insertAdjacentText' method allows to corrupt memory.
  - Handles 'Scrolling' event.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-037";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS12-037.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902682");
  script_version("$Revision: 8649 $");
  script_cve_id("CVE-2012-1523", "CVE-2012-1858", "CVE-2012-1872", "CVE-2012-1873",
                "CVE-2012-1874", "CVE-2012-1875", "CVE-2012-1876", "CVE-2012-1877",
                "CVE-2012-1878", "CVE-2012-1879", "CVE-2012-1880", "CVE-2012-1881",
                "CVE-2012-1882");
  script_bugtraq_id(53841, 53842, 53843, 53844, 53845, 53847, 53848, 53866,
                    53867, 53868, 53869, 53870, 53871);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-02-03 13:16:43 +0100 (Sat, 03 Feb 2018) $");
  script_tag(name:"creation_date", value:"2012-06-13 09:16:32 +0530 (Wed, 13 Jun 2012)");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2699988)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49412/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2699988");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1027147");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/49412");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-037");
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
if(!ieVer || !(ieVer =~ "^(6|7|8|9)")){
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
  if(version_in_range(version:dllVer, test_version:"6.0.2900.0000", test_version2:"6.0.2900.6211")||
     version_in_range(version:dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17109")||
     version_in_range(version:dllVer, test_version:"7.0.6000.20000", test_version2:"7.0.6000.21311")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19257")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23344")){
    security_message(0);
  }
  exit(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"6.0.3790.0000", test_version2:"6.0.3790.4985") ||
     version_in_range(version:dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17109")||
     version_in_range(version:dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21311")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19257")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23344")){
    security_message(0);
  }
  exit(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.18615")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.22837")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19271")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23358")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16445")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20550")){
    security_message(0);
  }
  exit(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Mshtml.dll version
  if(version_in_range(version:dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.17005")||
     version_in_range(version:dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.21197")||
     version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.17823")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.21975")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16445")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20550")){
    security_message(0);
  }
}
