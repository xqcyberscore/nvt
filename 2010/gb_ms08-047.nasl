###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms08-047.nasl 8296 2018-01-05 07:28:01Z teissa $
#
# Microsoft Windows IPsec Policy Processing Information Disclosure Vulnerability (953733)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801484");
  script_version("$Revision: 8296 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-05 08:28:01 +0100 (Fri, 05 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-21 15:57:21 +0100 (Tue, 21 Dec 2010)");
  script_cve_id("CVE-2008-2246");
  script_bugtraq_id(30634);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Microsoft Windows IPsec Policy Processing Information Disclosure Vulnerability (953733)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/31411");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2008/2351");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-047.mspx");
 
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : "Successful exploitation will result in systems ignoring IPsec policies and
  thus transmit data otherwise intended to be encrypted in clear text.
  Impact Level: System/Application");
  script_tag(name : "affected" , value : "Microsoft Windows Vista Service Pack 1 and prior.
  Microsoft Windows Server 2008 Service Pack 1 and prior.");
  script_tag(name : "insight" , value : "The flaw is caused by an error when the default IPsec policy is imported from
  a Windows Server 2003 domain to a Windows Server 2008 domain, which could
  cause all IPsec rules to be ignored and network traffic to be transmitted
  in clear text.");
  script_tag(name : "solution" , value : "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms08-047.mspx");
  script_tag(name : "summary" , value : "This host is missing a critical security update according to
  Microsoft Bulletin MS08-047.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");



if(hotfix_check_sp(winVista:2, win2008:2) <= 0){
  exit(0);
}

## Check Hotfix MS08-075
if(hotfix_missing(name:"953733") == 0){
 exit(0);
}
  
## Get System32 path
sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath, file_name:"Ipsecsvc.dll");
  if(dllVer)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Ipsecsvc.dll version  < 6.0.6001.18094
        if(version_is_less(version:dllVer, test_version:"6.0.6001.18094")){
            security_message(0);
        }
        exit(0);
      }
    }

    # Windows Server 2008
    else if(hotfix_check_sp(win2008:2) > 0)
    {
      SP = get_kb_item("SMB/Win2008/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Ipsecsvc.dll version  < 6.0.6001.18094
        if(version_is_less(version:dllVer, test_version:"6.0.6001.18094")){
            security_message(0);
        }
        exit(0);
      }
    }
  }
}
