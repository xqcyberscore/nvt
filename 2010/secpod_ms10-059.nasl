###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-059.nasl 8724 2018-02-08 15:02:56Z cfischer $
#
# Microsoft Windows Tracing Feature Privilege Elevation Vulnerabilities (982799)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary code
  with elevated privileges.

  Impact Level: System";
tag_affected = "Microsoft Windows 7

  Microsoft Windows Vista Service Pack 1/2 and prior.

  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The multiple flaws are due to,

   - Windows placing incorrect access control lists (ACLs) on registry keys for
     the Tracing Feature for Services.

   - A memory corruption error in the Tracing Feature for Services when handling
     certain strings read from the registry.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,

  http://www.microsoft.com/technet/security/Bulletin/MS10-059.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-059.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902231");
  script_version("$Revision: 8724 $");
  script_tag(name:"last_modification", value:"$Date: 2018-02-08 16:02:56 +0100 (Thu, 08 Feb 2018) $");
  script_tag(name:"creation_date", value:"2010-08-26 14:31:12 +0200 (Thu, 26 Aug 2010)");
  script_cve_id("CVE-2010-2555", "CVE-2010-2554");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_name("Microsoft Windows Tracing Feature Privilege Elevation Vulnerabilities (982799)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/982799");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60681");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2056");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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


if(hotfix_check_sp(winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

# Check for MS10-059 Hotfix
if(hotfix_missing(name:"982799") == 0){
 exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\system32\Rtutils.dll");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

# Windows Vista
if(hotfix_check_sp(winVista:2) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Rtutils.dll version < 6.0.6001.18495
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18495")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Rtutils.dll version < 6.0.6002.18274
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18274")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

# Windows Server 2008
else if(hotfix_check_sp(win2008:2) > 0)
{
  SP = get_kb_item("SMB/Win2008/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Rtutils.dll version < 6.0.6001.18495
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18495")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Rtutils.dll version < 6.0.6002.18274
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18274")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

# Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for Tcpip.sys version < 6.1.7600.16617	
  if(version_is_less(version:sysVer, test_version:"6.1.7600.16617")){
     security_message(0);
  }
}
