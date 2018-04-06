###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-083.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows IP-HTTPS Component Security Feature Bypass Vulnerability (2765809)
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation could allow attacker to bypass certain security
  restrictions.
  Impact Level: System";
tag_affected = "Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior";
tag_insight = "The flaw is due to error in the IP-HTTPS component, which fails to validate
  the certificates. This can lead to a revoked certificate being considered as
  valid.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-083";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-083.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901305");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-2549");
  script_bugtraq_id(56840);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-12-12 09:40:29 +0530 (Wed, 12 Dec 2012)");
  script_name("Microsoft Windows IP-HTTPS Component Security Feature Bypass Vulnerability (2765809)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51500/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2765809");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-083");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
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

## Variables Initialization
iphlpsvcPath = "";
iphlpsvcVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
iphlpsvcPath = smb_get_systemroot();
if(!iphlpsvcPath){
  exit(0);
}

## Get Version from Iphlpsvc.dll file
iphlpsvcVer = fetch_file_version(sysPath:iphlpsvcPath, file_name:"system32\Iphlpsvc.dll");

## Check for Iphlpsvc.dll version
## before 6.1.7600.17157 and 6.1.7600.22000 before 6.1.7600.21360 (RTM)
## before 6.1.7601.17989 and 6.1.7601.21000 before 6.1.7601.22150 (SP1)
if(iphlpsvcVer && (version_is_less(version:iphlpsvcVer, test_version:"6.1.7600.17157") ||
   version_in_range(version:iphlpsvcVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21359")||
   version_in_range(version:iphlpsvcVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17988")||
   version_in_range(version:iphlpsvcVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22149"))){
  security_message(0);
}
