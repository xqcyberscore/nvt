###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-065.nasl 8447 2018-01-17 16:12:19Z teissa $
#
# Microsoft Internet Information Services Remote Code Execution Vulnerabilities (2267960)
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow remote attackers to bypass restrictions,
  create a denial of service condition or compromise a vulnerable web server.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows 7
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.
  Microsoft Windows Server 2008 Service Pack 2 and prior.
  Microsoft Internet Information Services (IIS) version 5.1
  Microsoft Internet Information Services (IIS) version 6.0
  Microsoft Internet Information Services (IIS) version 7.0
  Microsoft Internet Information Services (IIS) version 7.5";
tag_insight = "- a stack overflow error in the ASP script processing code when processing
    specially crafted URL requests sent to active server pages, which could be
    exploited to cause a denial of service.
  - a buffer overflow error in the FastCGI module when processing malformed
    HTTP headers, which could be exploited by remote attackers to take complete
    control of the affected system via a specially crafted request.
  - an error when processing specially crafted URLs, which could be exploited
    to bypass authentication.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS10-065";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-065.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901151");
  script_version("$Revision: 8447 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 17:12:19 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-15 17:01:07 +0200 (Wed, 15 Sep 2010)");
  script_cve_id("CVE-2010-1899", "CVE-2010-2730", "CVE-2010-2731");
  script_bugtraq_id(43140, 43138, 41314);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Information Services Remote Code Execution Vulnerabilities (2267960)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2124261");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2386");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS10-065");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_ms_iis_detect_win.nasl");
  script_mandatory_keys("MS/IIS/Ver", "SMB/WindowsVersion");
  script_require_ports(139, 445);
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

## Confirm IIS
iisVer = get_kb_item("MS/IIS/Ver");
if(!iisVer){
  exit(0);
}

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

## Hotfix check
if(hotfix_missing(name:"2267960") == 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

sysVer = fetch_file_version(sysPath, file_name:"system32\inetsrv\Asp.dll");
if(!sysVer){
  exit(0);
}

## Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 3" >< SP)
  {
    ## Grep for Asp.dll version < 5.1.2600.6007
    if(version_is_less(version:sysVer, test_version:"5.1.2600.6007")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 2003
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    ## Grep for Asp.dll version < 6.0.3790.4735
    if(version_is_less(version:sysVer, test_version:"6.0.3790.4735")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows Vista and Windows Server 2008
else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if(!SP) {
    SP = get_kb_item("SMB/Win2008/ServicePack");
  }

  if("Service Pack 1" >< SP)
  {
    ## Grep for Asp.dll version < 7.0.6001.18497
    if(version_is_less(version:sysVer, test_version:"7.0.6001.18497")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    ## Grep for Asp.dll version < 7.0.6002.18276
    if(version_is_less(version:sysVer, test_version:"7.0.6002.18276")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  ## Grep for Asp.dll version < 7.5.7600.16620
  if(version_is_less(version:sysVer, test_version:"7.5.7600.16620")){
    security_message(0);
  }
}
