###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-092.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Hyper-V Privilege Elevation Vulnerability (2893986)
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901226");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3898");
  script_bugtraq_id(63562);
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-11-15 12:40:59 +0530 (Fri, 15 Nov 2013)");
  script_name("Microsoft Hyper-V Privilege Elevation Vulnerability (2893986)");

  tag_summary =
"This host is missing a important security update according to
Microsoft Bulletin MS13-092.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The issue is triggered when handling the value of a data structure, allowing
a memory address with an invalid address to be used.";

  tag_impact =
"Successful exploitation allows guest OS users to execute arbitrary code in
all guest OS instances, and allows guest OS users to cause a denial of service
(host OS crash) via a guest-to-host hypercall with a crafted function parameter

Impact Level: Application";

  tag_affected =
"Microsoft Windows Server 2012
Microsoft Windows 8 x64 Edition";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and update
mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms13-092";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/55550/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2893986");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms13-092");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
sysPath = "";
sysVer = "";

## Check for OS and Service Pack
## Need to add Microsoft Windows 8 x64 Edition once we have the imag i.e win8x64:1
if(hotfix_check_sp(win2012:1) <= 0){
  exit(0);
}

## COnfirm Hyper-V is installed by checking vmms.exe
if(!registry_key_exists(key:"SOFTWARE\Classes\AppID\vmms.exe")){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Hvax64.exe file
sysVer = fetch_file_version(sysPath, file_name:"system32\Hvax64.exe");
if(!sysVer){
  exit(0);
}

## Windows 2012
if(hotfix_check_sp(win2012:1) > 0)
{
  ## Check for Hvax64.exe version
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16729")){
    security_message(0);
  }
  exit(0);
}
