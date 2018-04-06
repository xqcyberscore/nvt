###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms11-028.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Microsoft .NET Framework Remote Code Execution Vulnerability (2484015)
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

tag_impact = "Successful exploitation could allow remote attackers to crash an affected
  system or execute arbitrary code by tricking a user into visiting a specially
  crafted web page.
  Impact Level: System/Application";
tag_affected = "Microsoft .NET Framework 4.0
  Microsoft .NET Framework 2.0 Service Pack 2
  Microsoft .NET Framework 3.5 Service Pack 1";
tag_insight = "The flaw is caused by a stack corruption error in the x86 JIT compiler within
  the .NET Framework when compiling certain types of function calls, which
  could be exploited by remote attackers to execute arbitrary code by tricking
  a user into visiting a specially crafted web page.";
tag_solution = "Run Windows Update and update the listed hotfixes or download and
  update mentioned hotfixes in the advisory from the below link,
  http://technet.microsoft.com/en-us/security/bulletin/ms11-028";
tag_summary = "This host is missing a critical security update according to
  Microsoft Bulletin MS11-028.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902502");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)");
  script_cve_id("CVE-2010-3958");
  script_bugtraq_id(47223);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (2484015)");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2484015");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/0945");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms11-028");

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

#ecpod_ms11-028.nasl  Check for OS and Service Pack
if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2008:3, win7:2) <= 0){
  exit(0);
}

## MS11-028 Hotfix
if((hotfix_missing(name:"2446704") == 0) || (hotfix_missing(name:"2446708") == 0) ||
   (hotfix_missing(name:"2449741") == 0) || (hotfix_missing(name:"2449742") == 0) ||
   (hotfix_missing(name:"2446709") == 0) || (hotfix_missing(name:"2446710") == 0) ){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if("\Microsoft.NET\Framework" >< path)
  {
    ## Get version from mscorlib.dll file
    dllVer = fetch_file_version(sysPath:path, file_name:"mscorlib.dll");
    if(dllVer)
    {
      ## Windows XP and Windows 2003
      if(hotfix_check_sp(xp:4, win2003:3) > 0)
      {
        ## .NET Framework .NET Framework 4, 3.5 Service Pack 1 and 2.0
        if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.224")||
           version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.430")||
           version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3619")||
           version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5652"))
        {
          security_message(0);
          exit(0);
        }
      }

      ## Windows Vista and Windows Server 2008
      if(hotfix_check_sp(winVista:3, win2008:3) > 0)
      {
        SP = get_kb_item("SMB/WinVista/ServicePack");

        if(!SP) {
          SP = get_kb_item("SMB/Win2008/ServicePack");
        }

        ## .NET Framework 4
        ## .NET Framework 3.5 Service Pack 1 and the .NET Framework 2.0 Service Pack 2
        if("Service Pack 1" >< SP)
        {
          if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.224")||
             version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.430")||
             version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3618")||
             version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5652"))
          {
            security_message(0);
            exit(0);
          }
        }

        ## .NET Framework 4
        ## .NET Framework 3.5 Service Pack 1 and the .NET Framework 2.0 Service Pack 2
        if("Service Pack 2" >< SP)
        {
          if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.224")||
             version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.430")||
             version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4210")||
             version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5652"))
          {
            security_message(0);
            exit(0);
          }
        }
      }

      ## .NET Framework 4 and
      ## .NET Framework 3.5.1 on Windows 7
      if(hotfix_check_sp(win7:2) > 0)
      {
        ## Check for mscorlib.dll version
       if(version_in_range(version:dllVer, test_version:"4.0.30319.200", test_version2:"4.0.30319.224")||
          version_in_range(version:dllVer, test_version:"4.0.30319.400", test_version2:"4.0.30319.430")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5000", test_version2:"2.0.50727.5443")||
          version_in_range(version:dllVer, test_version:"2.0.50727.5600", test_version2:"2.0.50727.5652")||
          version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4958"))
       {
         security_message(0);
         exit(0);
       }
      }
    }
  }
}
