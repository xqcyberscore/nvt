###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms10-083.nasl 8246 2017-12-26 07:29:20Z teissa $
#
# Microsoft Windows Shell and WordPad COM Validation Vulnerability (2405882)
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

tag_impact = "Successful exploitation will allow remote attacker to arbitrary code by
  convincing a user to open a specially crafted WordPad file, or open or select
  a shortcut file that is present on a network or a WebDAV share.
  Impact Level: System/Application.";
tag_affected = "Microsoft Windows 7
  Microsoft Windows XP Service Pack 3 and prior
  Microsoft Windows Vista Service Pack 2 and prior
  Microsoft Windows Server 2003 Service Pack 2 and prior
  Microsoft Windows Server 2008 Service Pack 2 and prior";
tag_insight = "The flaw is caused by an error in the way Windows Shell and WordPad
  validate COM object instantiation, which could allow attackers to execute
  arbitrary code.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://www.microsoft.com/technet/security/bulletin/ms10-083.mspx";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS10-083.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902262");
  script_version("$Revision: 8246 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-26 08:29:20 +0100 (Tue, 26 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-10-13 17:10:12 +0200 (Wed, 13 Oct 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-1263");
  script_name("Microsoft Windows Shell and WordPad COM Validation Vulnerability (2405882)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/979687");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/979688");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/2630");

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

## This function will return the version of the given file
function Get_dllversion(path, dllfile)
{
  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:path);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                     string:path + dllfile);
  sysVer = GetVer(file:file, share:share);
  if(isnull(sysVer)){
    return 0;
  }
  else
    return sysVer;
}

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:1) <= 0){
  exit(0);
}

if(hotfix_missing(name:"979687") == 1)
{
  sysPath =  registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                               item:"ProgramFilesDir");
  if(sysPath)
  {
    sysVer =  Get_dllversion(path:sysPath, dllfile:"\Windows NT\Accessories\Wordpad.exe");
    if(sysVer)
    {
      ## Windows XP
      if(hotfix_check_sp(xp:4) > 0)
      {
        SP = get_kb_item("SMB/WinXP/ServicePack");
        if("Service Pack 3" >< SP)
        {
          ## Grep for Wordpad.exe version < 5.1.2600.6010
          if(version_is_less(version:sysVer, test_version:"5.1.2600.6010")){
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
          # Grep for  Wordpad.exe version < 5.1.2600.6010
          if(version_is_less(version:sysVer, test_version:"5.1.2600.6010")){
            security_message(0);
          }
          exit(0);
        }
        security_message(0);
      }
    }
  }
}

if((hotfix_missing(name:"979687") == 0) && (hotfix_missing(name:"979688") == 0)){
  exit(0);
}

sysPath =  registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                               item:"ProgramFilesDir");
if(sysPath)
{
  sysVer1 =  Get_dllversion(path:sysPath, dllfile:"\Windows NT\Accessories\Wordpad.exe");
  path = sysPath - "\Program Files";

  sysVer2 =  Get_dllversion(path:path, dllfile:"\Windows\System32\Msshsq.dll");
  if(sysVer1 && sysVer2)
  {
    # Windows Vista
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        # Grep for Wordpad.exe version < 6.0.6001.18498
        # Grep for Msshsq.dll version  < 6.0.6001.18470
        if(version_is_less(version:sysVer1, test_version:"6.0.6001.18498") ||
           version_is_less(version:sysVer2, test_version:"6.0.6001.18470"))
        {
           security_message(0);
           exit(0);
        }
      }

      if("Service Pack 2" >< SP)
      {
        ## Grep for Wordpad.exe version <  6.0.6002.18277
        if(version_is_less(version:sysVer1, test_version:"6.0.6002.18277"))
        {
          security_message(0);
          exit(0);
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
        # Grep for Wordpad.exe version < 6.0.6001.18498
        # Grep for Msshsq.dll version  < 6.0.6001.18470
        if(version_is_less(version:sysVer1, test_version:"6.0.6001.18498") ||
           version_is_less(version:sysVer2, test_version:"6.0.6001.18470"))
        {
          security_message(0);
          exit(0);
        }
      }

      if("Service Pack 2" >< SP)
      {
         ## Grep for Wordpad.exe version <  6.0.6002.18277
         if(version_is_less(version:sysVer1, test_version:"6.0.6002.18277"))
         {
           security_message(0);
           exit(0);
         }
      }
      security_message(0);
    }
  }

  sysVer3 =  Get_dllversion(path:path, dllfile:"\Windows\System32\Structuredquery.dll");
  if(sysVer3 && sysVer1)
  {
     ## Windows 7
     if(hotfix_check_sp(win7:1) > 0)
     {
        # Grep for Wordpad.exe version < 6.1.7600.16624
        # Grep for Structuredquery.dll version  < 7.0.7600.16587
        if(version_is_less(version:sysVer1, test_version:"6.1.7600.16624") ||
           version_is_less(version:sysVer3, test_version:"7.0.7600.16587"))
        {
          security_message(0);
          exit(0);
        }
     }
  }
}
