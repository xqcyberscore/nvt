###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms14-006.nasl 9354 2018-04-06 07:15:32Z cfischer $
#
# Microsoft Windows IPv6 Denial of Service Vulnerability (2904659)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901228");
  script_version("$Revision: 9354 $");
  script_cve_id("CVE-2014-0254");
  script_bugtraq_id(65409);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-02-12 09:23:09 +0530 (Wed, 12 Feb 2014)");
  script_name("Microsoft Windows IPv6 Denial of Service Vulnerability (2904659)");

  tag_summary =
"This host is missing a important security update according to Microsoft
Bulletin MS14-006.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"Flaw is due to incomplete validation of TCP/IP network packets.";

  tag_impact =
"Successful exploitation will allow attackers to cause denial of service
condition.

Impact Level: System";

  tag_affected =
"Microsoft Windows 8 x32/x64
Microsoft Windows Server 2012";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
https://technet.microsoft.com/en-us/security/bulletin/ms14-006";

  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/56775/");
  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2904659");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/security/bulletin/ms14-006");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

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
if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) <= 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from tcpip.sys file
sysVer = fetch_file_version(sysPath, file_name:"system32\drivers\tcpip.sys");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0)
{
  ## Check for tcpip.sys version
  if(version_is_less(version:sysVer, test_version:"6.2.9200.16754") ||
     version_in_range(version:sysVer, test_version:"6.2.9200.20000", test_version2:"6.2.9200.20866")){
    security_message(0);
  }
  exit(0);
}
