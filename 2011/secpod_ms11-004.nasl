###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-004.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Internet Information Services (IIS) FTP Service Remote Code Execution Vulnerability (2489256)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to cause a denial of
  service and possibly execute arbitrary code via a crafted FTP request that
  triggers memory corruption.
  Impact Level: System/Application";
tag_affected = "Microsoft Internet Information Services (IIS) version 7.0
   - On Microsoft Windows Vista/2008 server Service Pack 2 and prior
  Microsoft Internet Information Services (IIS) version 7.5
   - On Microsoft Windows 7 Service Pack 1 and prior";
tag_insight = "The flaw is due to a boundary error when encoding Telnet IAC
  characters in a FTP response. This can be exploited without authenticating
  to the FTP service to cause a heap-based buffer overflow by sending an overly
  long, specially crafted FTP request.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms11-004.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-004.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901183");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2010-3972");
  script_bugtraq_id(45542);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-09 17:14:46 +0100 (Wed, 09 Feb 2011)");
  script_name("Internet Information Services (IIS) FTP Service Remote Code Execution Vulnerability (2489256)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42713");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/842372");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15803/");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1024921");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/3305");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
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
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Check for OS and Service Pack
if(hotfix_check_sp(winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-004 Hotfix (2489256)
if(hotfix_missing(name:"2489256") == 0){
  exit(0);
}

## Get System Path
sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

## Get Version from Ftpsvc.dll file
dllVer = fetch_file_version(sysPath, file_name:"system32\inetsrv\ftpsvc.dll");
if(!dllVer){
  exit(0);
}

## Windows Vista and Windows Server 2008
if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  ## Check for Ftpsvc.dll version
  if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6545.14978")||
     version_in_range(version:dllVer, test_version:"7.5.7600.0", test_version2:"7.5.7600.14977")||
     version_in_range(version:dllVer, test_version:"7.5.7055.0", test_version2:"7.5.7055.14309")){
    security_message(0);
  }
  exit(0);
}

## Windows 7
else if(hotfix_check_sp(win7:2) > 0)
{
  ## Check for Ftpsvc.dll version
  if(version_is_less(version:dllVer, test_version:"7.5.7600.16748") ||
     version_in_range(version:dllVer, test_version:"7.5.7600.20000", test_version2:"7.5.7600.20887")||
     version_in_range(version:dllVer, test_version:"7.5.7601.17000", test_version2:"7.5.7601.17549")||
     version_in_range(version:dllVer, test_version:"7.5.7601.21000", test_version2:"7.5.7601.21648")){
    security_message(0);
  }
}
