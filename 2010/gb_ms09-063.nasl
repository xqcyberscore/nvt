###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms09-063.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Microsoft Web Services on Devices API Remote Code Execution Vulnerability (973565)
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

tag_impact = "Successful exploitation will let the remote attackers attackers to execute
  arbitrary code by sending a specially crafted message to the WSD TCP ports
  5357 or 5358.
  Impact Level: System/Application";
tag_affected = "Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The flaws is caused by a memory corruption error in the Web Services on Devices
  API (WSDAPI), on both clients and servers, when processing a WSD message
  with malformed headers.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-063.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-063.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801480");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-11-25 08:29:59 +0100 (Thu, 25 Nov 2010)");
  script_cve_id("CVE-2009-2512");
  script_bugtraq_id(36919);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Web Services on Devices API Remote Code Execution Vulnerability (973565)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37314/");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3189");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-063.mspx");
  
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(winVista:3, win2008:3) <= 0){
  exit(0);
}

## Check Hotfix MS09-063
if(hotfix_missing(name:"973565") == 0){
  exit(0);
}

## Get System Path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\System32\Wsdapi.dll");

## Get File Version
dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

# Windows Vista
if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Wsdapi.dll version < 6.0.6001.18306
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18306")){
      security_message(0);
    }
      exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Wsdapi.dll version < 6.0.6002.18085
      if(version_is_less(version:dllVer, test_version:"6.0.6002.18085")){
      security_message(0);
    }
      exit(0);
  }
  security_message(0);
}

# Windows Server 2008
else if(hotfix_check_sp(win2008:3) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Wsdapi.dll version < 6.0.6001.18306
    if(version_is_less(version:dllVer, test_version:"6.0.6001.18306")){
      security_message(0);
    }
     exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Wsdapi.dll version < 6.0.6002.18085
    if(version_is_less(version:dllVer, test_version:"6.0.6002.18085")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
