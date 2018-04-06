###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms14-026.nasl 9354 2018-04-06 07:15:32Z cfischer $
#
# Microsoft .NET Framework Privilege Elevation Vulnerability (2958732)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.804452");
  script_version("$Revision: 9354 $");
  script_cve_id("CVE-2014-1806");
  script_bugtraq_id(67286);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-05-14 16:10:33 +0530 (Wed, 14 May 2014)");
  script_tag(name:"solution_type", value: "VendorFix");
  script_name("Microsoft .NET Framework Privilege Elevation Vulnerability (2958732)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Bulletin MS14-026.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to the framework not properly restricting access to certain
application objects related to TypeFilterLevel checks.";

  tag_impact =
"Successful exploitation could allow an attacker to bypass certain security
restrictions.

Impact Level: Application";

  tag_affected =
"Microsoft .NET Framework 1.1, 2.0, 3.5, 3.5.1, 4.0 and 4.5 and 4.5.1";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
http://technet.microsoft.com/en-us/security/bulletin/ms14-026";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/58271");
  script_xref(name : "URL" , value : "http://support.microsoft.com/kb/2958732");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/bulletin/ms14-026");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variables Initialization
key = "";
item = "";
path = "";
dllVer = "";
dllv4 = "";
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2,
                   win2008:3, win2008r2:2, win8:1, win8_1:1, win8_1x64:1, win2012:1) <= 0){
  exit(0);
}

## Confirm .NET
key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Try to Get Version
foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if(path && "\Microsoft.NET\Framework" >< path)
  {
    ## Get version from system.runtime.remoting.dll file
    dllVer = fetch_file_version(sysPath:path, file_name:"system.runtime.remoting.dll");
    if(dllVer)
    {
      ## .NET Framework 4 on Windows Server 2003, Windows Vista, Windows Server 2008,
      ## Windows 7 and Windows Server 2008 R2: May 13, 2014
      if((hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2) > 0) &&
        (version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1022")||
         version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2035")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 4.5.1 on Windows 7 Service Pack 1, Windows Server 2008 R2 Service Pack 1,
      ## Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2: May 13, 2014
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34107")||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36105")))
      {
        security_message(0);
        exit(0);
      }

      ## NET Framework 4.5.1 on Windows 8, and Windows Server 2012: May13, 2014
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34106")||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36104")))
      {
        security_message(0);
        exit(0);
      }


     ## .NET Framework 4.5.1 on Windows 8.1, and Windows Server 2012 R2 for systems that have
     ## update 2919355 installed: May 13, 2014
     ## Currently not supporting for Windows Server 2012 R2
     if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
       (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34106")||
        version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36114")))
      {
        security_message(0);
        exit(0);
      }

      ##.NET Framework 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1: May 13, 2014
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5482")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7056")))
      {
        security_message(0);
        exit(0);
      }

      ##.NET Framework 3.5 on Windows 8 and Windows Server 2012: May 13, 2014
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6415")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7054")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 3.5 on Windows 8.1 and Windows Server 2012 R2
      ## Currently not supporting for Windows Server 2012 R2
      if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
       (version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8002")||
        version_in_range(version:dllVer, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8605")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and
      ## Windows Server 2008 Service Pack 2: May 13, 2014
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4251")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7056")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Server 2003: May 13, 2014
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3658")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7054")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 1.1 Service Pack 1 on Windows Server 2003 Service Pack 2 32-bit Edition: May 13, 2014
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2505")))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
