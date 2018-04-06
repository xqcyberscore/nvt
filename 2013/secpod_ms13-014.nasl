###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms13-014.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Microsoft Windows NFS Server Denial of Service Vulnerability (2790978)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to denial of service.
  Impact Level: System";

tag_affected = "Microsoft Windows Server 2008 R2 Service Pack 2 and prior";
tag_insight = "The flaw is due to a NULL pointer dereference error when handling file
  operations on a read only share and can be exploited to cause the system
  to stop responding and restart.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms13-014";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS13-014.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902951");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-1281");
  script_bugtraq_id(57853);
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-02-13 15:29:45 +0530 (Wed, 13 Feb 2013)");
  script_name("Microsoft Windows NFS Server Denial of Service Vulnerability (2790978)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/52138/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2790978");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1028129");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms13-014");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
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

## Variable Initialization
sysPath = "";
exeVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2008r2:2) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Nfssvc.exe file
exeVer = fetch_file_version(sysPath, file_name:"system32\Nfssvc.exe");
if(!exeVer){
  exit(0);
}

## Windows 2008 R2
if(hotfix_check_sp(win2008r2:2) > 0)
{
  ## Check for Nfssvc.exe version
  if(version_is_less(version:exeVer, test_version:"6.1.7600.16385") ||
     version_in_range(version:exeVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.21413")||
     version_in_range(version:exeVer, test_version:"6.1.7601.17000", test_version2:"6.1.7601.17513")||
     version_in_range(version:exeVer, test_version:"6.1.7601.21000", test_version2:"6.1.7601.22206")){
    security_message(0);
  }
}

