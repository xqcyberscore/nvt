###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms09-040.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Microsoft Windows Message Queuing Privilege Escalation Vulnerability (971032)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-01-13
#        - To detect file version 'Mqsvc.exe' on vista
#
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code with
  SYSTEM level privileges and completely compromise the affected system.
  Impact Level: System";
tag_affected = "Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows XP Service Pack 2 and prior.
  Microsoft Windows 2003 Service Pack 2 and prior.
  Microsoft Windows Vista Service Pack 2 and prior.";
tag_insight = "An error occurs while parsing malicious IOCTL requests sent to the Message Queuing
  service (MSMQ) because the input data is not adequately sanitised before being
  passed into the buffer.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/Bulletin/MS09-040.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS09-040.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900908");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-08-13 19:09:22 +0200 (Thu, 13 Aug 2009)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-1922");
  script_bugtraq_id(35969);
  script_name("Microsoft Windows Message Queuing Privilege Escalation Vulnerability (971032)");


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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36214/");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/971032");
  script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/Bulletin/MS09-040.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3) <= 0){
  exit(0);
}

# MS09-040 Hotfix (971032)
if(hotfix_missing(name:"971032") == 0){
  exit(0);
}

exePath = registry_get_sz(item:"Install Path",
                          key:"SOFTWARE\Microsoft\COM3\Setup");
if(!exePath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath +
                                                            "\Mqsvc.exe");
exeVer = GetVer(file:file, share:share);
if(!exeVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  # Check for Mqsvc.exe version 5.0 < 5.0.0.808
  if(version_in_range(version:exeVer, test_version:"5.0",
                      test_version2:"5.0.0.807")){
    security_message(0);
  }
  exit(0);
}
else if(hotfix_check_sp(xp:3) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Check for Mqsvc.exe version 5.1 < 5.1.0.1111
    if(version_in_range(version:exeVer, test_version:"5.1",
                        test_version2:"5.1.0.1110")){
      security_message(0);
    }
    exit(0);
  }
}
else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 2" >< SP)
  {
    # Check for Mqsvc.exe version 5.2 < 5.2.2007.4530
    if(version_in_range(version:exeVer, test_version:"5.2",
                        test_version2:"5.2.2007.4529")){
      security_message(0);
    }
    exit(0);
  }
  security_message(0);
}

## Get System Path
sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                          item:"PathName");
if(!sysPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:sysPath + "\System32\Mqsvc.exe");

## Get File Version
exeVer = GetVer(file:file, share:share);
if(exeVer)
{
  # Windows Vista
  if(hotfix_check_sp(winVista:3) > 0)
  {
    # Grep for Mqsvc.exe version < 6.0.6000.16871
    if(version_is_less(version:exeVer, test_version:"6.0.6000.16871")){
        security_message(0);
    }
      exit(0);
  }
}
