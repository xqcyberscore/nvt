###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-001.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Vulnerabilities in SMB Could Allow Remote Code Execution (958687)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright (c) 2009 SecPod, http://www.secpod.org
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

tag_impact = "Successful exploitation could allow remote unauthenticated attackers
  to cause denying the service by sending a specially crafted network message
  to a system running the server service.
  Impact Level: System/Network";
tag_affected = "Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.";
tag_insight = "The issue is due to the way Server Message Block (SMB) Protocol software
  handles specially crafted SMB packets.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms09-001.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-001.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900069");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-01-14 06:10:19 +0100 (Wed, 14 Jan 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4114", "CVE-2008-4834", "CVE-2008-4835");
  script_bugtraq_id(31179);
  script_name("Vulnerabilities in SMB Could Allow Remote Code Execution (958687)");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6463");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms09-001.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}

# Check Hotfix Missing 958687 (MS09-001)
if(hotfix_missing(name:"958687") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\drivers\Srv.sys");

sysVer = GetVer(file:file, share:share);
if(!sysVer){
  exit(0);
}

# Windows 2K
if(hotfix_check_sp(win2k:5) > 0)
{
  # Grep for Srv.sys version < 5.0.2195.7222
  if(version_is_less(version:sysVer, test_version:"5.0.2195.7222")){
    security_message(0);
  }
  exit(0);
}

# Windows XP
if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Grep for Srv.sys < 5.1.2600.3491
    if(version_is_less(version:sysVer, test_version:"5.1.2600.3491")){
      security_message(0);
    }
    exit(0);
  }
  else if("Service Pack 3" >< SP)
  {
    # Grep for Srv.sys < 5.1.2600.5725
    if(version_is_less(version:sysVer, test_version:"5.1.2600.5725")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

# Windows 2003
if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP)
  {
    # Grep for Srv.sys version < 5.2.3790.3260
    if(version_is_less(version:sysVer, test_version:"5.2.3790.3260")){
      security_message(0);
    }
    exit(0);
  }
  else if("Service Pack 2" >< SP)
  {
    # Grep for Srv.sys version < 5.2.3790.4425
    if(version_is_less(version:sysVer, test_version:"5.2.3790.4425")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}
