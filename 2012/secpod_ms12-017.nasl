###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms12-017.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Microsoft Windows DNS Server Denial of Service Vulnerability (2647170)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attacker to execute arbitrary
  code or to cause the DNS server to stop responding or to restart.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.";
tag_insight = "The flaws are exists when Windows DNS server processing certain lookup
  queries and can be exploited to restart the DNS server.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms12-017";
tag_summary = "This host is missing an important security update according to
  Microsoft Bulletin MS12-017.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902906");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(52374);
  script_cve_id("CVE-2012-0006");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-14 08:31:02 +0530 (Wed, 14 Mar 2012)");
  script_name("Microsoft Windows DNS Server Denial of Service Vulnerability (2647170)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48394");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2647170");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms12-017");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = "";
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2008:3) <= 0){
  exit(0);
}

if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\DNS")){
  exit(0);
}

## MS12-017 Hotfix 2647170
if((hotfix_missing(name:"2647170") == 0)){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version for Dns.exe
sysVer = fetch_file_version(sysPath, file_name:"system32\Dns.exe");
if(!sysVer){
  exit(0);
}

## Windows 2003
if(hotfix_check_sp(win2003:3) > 0)
{
  ## Check for Dns.exe version
  if(version_is_less(version:sysVer, test_version:"5.2.3790.4957")){
    security_message(0);
  }
  exit(0);
}

## Windows Server 2008
if(hotfix_check_sp(win2008:3) > 0)
{
  ## Check for Dns.exe version
  if(version_is_less(version:sysVer, test_version:"6.0.6002.18557")||
     version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22762")){
    security_message(0);
  }
}
