###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-030.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# Microsoft Remote Desktop Tampering Vulnerability (2969259)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802077");
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2014-0296");
  script_bugtraq_id(67865);
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-06-11 08:26:33 +0530 (Wed, 11 Jun 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft Remote Desktop Tampering Vulnerability (2969259)");

  tag_summary =
"This host is missing an important security update according to Microsoft
Bulletin MS14-030.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw is due Remote Desktop does not use robust encryption for an RDP session.";

  tag_impact =
"Successful exploitation will allow attacker gain access to and modify
potentially sensitive RDP information during an active session.

Impact Level: Application";

  tag_affected =
"Microsoft Windows 8 x32/x64
Microsoft Windows 8.1 x32/x64
Microsoft Windows Server 2012
Microsoft Windows Server 2012 R2
Microsoft Windows 7 x32/x64 Service Pack 1 and prior";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/library/security/ms14-030";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2965788");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2966034");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/ms14-030");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_reg_enum.nasl");
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
if(hotfix_check_sp(win7:2, win7x64:2, win8:1, win8x64:1,
                   win2012:1, win8_1:1, win8_1x64:1) <= 0)
{
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

## Get Version from Rdpcorets.dll file
sysVer = fetch_file_version(sysPath, file_name:"\system32\Rdpcorets.dll");
if(!sysVer){
  exit(0);
}

## Windows 7 and Windows 2008 R2
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  ## Check for Rdpcorets.dll version
  if(version_is_less(version:sysVer, test_version:"6.1.7601.18465") ||
     version_in_range(version:sysVer, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22677") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16911") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21034")){
    security_message(0);
  }
  exit(0);
}

## Windows 8 and 2012
else if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  ## Check for Rdpcorets.dll version
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16912") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21034")){
    security_message(0);
  }
  exit(0);
}

## Windows 8.1
## Currently not supporting for Windows Server 2012 R2
else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
  ## Check for Rdpcorets.dll version
  if(version_in_range(version:sysVer, test_version:"6.3.9600.16000", test_version2:"6.3.9600.16662") ||
     version_in_range(version:sysVer, test_version:"6.3.9600.17000", test_version2:"6.3.9600.17115")){
    security_message(0);
  }
  exit(0);
}
