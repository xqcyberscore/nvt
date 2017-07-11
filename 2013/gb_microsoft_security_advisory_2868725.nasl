###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_security_advisory_2868725.nasl 6234 2017-05-29 10:42:27Z cfi $
#
# Microsoft RC4 Disabling Security Advisory (2868725)
#
# Authors:
# Shakeel <bhatshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804142";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6234 $");
  script_tag(name:"cvss_base", value:"8.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-05-29 12:42:27 +0200 (Mon, 29 May 2017) $");
  script_tag(name:"creation_date", value:"2013-11-14 11:28:18 +0530 (Thu, 14 Nov 2013)");
  script_name("Microsoft RC4 Disabling Security Advisory (2868725)");

  tag_summary =
"This host is missing an important security update according to Microsoft
advisory (2868725).";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to security issue in RC4 stream cipher used in Transport
Layer Security(TLS) and Secure Socket Layer(SSL).";

  tag_impact =
"Successful exploitation will allow an attacker to perform man-in-the-middle
attacks and recover plain text from encrypted sessions.";

  tag_affected =
"Microsoft Windows 7 x32/x64 Service Pack 1 and prior
Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1 and prior
Microsoft Windows 8 x32/x64
Microsoft Windows Server 2012";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://support.microsoft.com/kb/2868725";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2868725");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/advisory/2868725");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_smb_windows_detect.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable Initialization
sysPath = "";
schannelVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8:1, win8x64:1, win2012:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Schannel.dll file
schannelVer = fetch_file_version(sysPath, file_name:"system32\schannel.dll");
if(!schannelVer){
  exit(0);
}

## Windows 7 and Windows 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
        ## Check for Schannel.dll version
  if(version_is_less(version:schannelVer, test_version:"6.1.7601.18270") ||
     version_in_range(version:schannelVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22464")){
    security_message(0);
  }
  exit(0);
}

## Win 8 and 2012
else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  ## Get Version from Schannel.dll file
  if(version_is_less(version:schannelVer, test_version:"6.2.9200.16722") ||
     version_in_range(version:schannelVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20831")){
    security_message(0);
  }
  exit(0);
}
