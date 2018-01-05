###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-075.nasl 8274 2018-01-03 07:28:17Z teissa $
#
# Microsoft Windows Media Player Network Sharing Remote Code Execution Vulnerability (2281679)
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

tag_impact = "Successful exploitation could allow remote attackers to take control of a
  vulnerable system via specially crafted packets.
  Impact Level: System";
tag_affected = "Microsoft Windows 7
  Microsoft Windows Vista Service Pack 2 and prior.";
tag_insight = "The flaw is caused by a use-after-free error in the Windows Media Player
  Network Sharing Service 'wmpnetwk.exe' when processing Real Time Streaming
  Protocol (RTSP) packets.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS10-075.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-075.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902263");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_cve_id("CVE-2010-3225");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Media Player Network Sharing Remote Code Execution Vulnerability (2281679)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2281679");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2622");

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


if(hotfix_check_sp(winVista:3, win7:1) <= 0){
  exit(0);
}

# Check for MS10-075 Hotfix
if(hotfix_missing(name:"2281679") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\system32\Wmpmde.dll");

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
    # Grep for Wmpmde.dll version < 11.0.6001.7009
    if(version_is_less(version:sysVer, test_version:"11.0.6001.7009")){
      security_message(0);
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    # Grep for Wmpmde.dll version < 11.0.6002.18297
    if(version_is_less(version:sysVer, test_version:"11.0.6002.18297")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

else if(hotfix_check_sp(win7:1) > 0)
{
  # Grep for Wmpmde.dll version < 6.1.7600.16617
  if(version_is_less(version:sysVer, test_version:"12.0.7600.16661")){
     security_message(0);
  }
}
