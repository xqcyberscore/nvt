###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-058.nasl 8187 2017-12-20 07:30:09Z teissa $
#
# Microsoft Windows TCP/IP Privilege Elevation Vulnerabilities (978886)
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

tag_impact = "Successful exploitation could allow remote attackers to cause a denial of service
  or by local attackers to gain elevated privileges.
  Impact Level: System";
tag_affected = "Micorsoft Windows 7
  Microsoft Windows Vista Service Pack 1/2 and prior.
  Microsoft Windows Server 2008 Service Pack 1/2 and prior.";
tag_insight = "The multiple flaws are due to,
  - An integer overflow error in the Windows 'TCP/IP' stack when handling data
    copied from user mode, which could be exploited by malicious users to execute
    arbitrary code with elevated privileges.
  - An error in the Windows Networking stack when processing malformed packets,
    which could be exploited by remote attackers to cause an affected system
    to stop responding.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/MS10-058";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-058.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902232");
  script_version("$Revision: 8187 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-20 08:30:09 +0100 (Wed, 20 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-26 14:31:12 +0200 (Thu, 26 Aug 2010)");
  script_cve_id("CVE-2010-1892", "CVE-2010-1893");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Microsoft Windows  TCP/IP Privilege Elevation Vulnerabilities (978886)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/978886");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2055");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/MS10-058");

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

# Check for MS10-058 Hotfix
if(hotfix_missing(name:"978886") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\system32\drivers\tcpip.sys");

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
    # Grep for Tcpip.sys version < 6.0.6001.18493
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18493") ||
       version_in_range(version:sysVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22712")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Tcpip.sys version < 6.0.6002.18272
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18272") ||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22424")){
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
    # Grep for Tcpip.sys version < 6.0.6001.18493
    if(version_is_less(version:sysVer, test_version:"6.0.6001.18493") ||
       version_in_range(version:sysVer, test_version:"6.0.6001.22000", test_version2:"6.0.6001.22712")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Tcpip.sys version < 6.0.6002.18272
    if(version_is_less(version:sysVer, test_version:"6.0.6002.18272") ||
       version_in_range(version:sysVer, test_version:"6.0.6002.22000", test_version2:"6.0.6002.22424")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

# Windows 7
else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for Tcpip.sys version < 6.1.7600.16610
   if(version_is_less(version:sysVer, test_version:"6.1.7600.16610") ||
      version_in_range(version:sysVer, test_version:"6.1.7600.20000", test_version2:"6.1.7600.20732")){
     security_message(0);
  }
}
