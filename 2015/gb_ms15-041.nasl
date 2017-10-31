###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms15-041.nasl 7582 2017-10-26 11:56:51Z cfischer $
#
# Microsoft Windows .NET Framework Information Disclosure Vulnerability (3048010)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805060");
  script_version("$Revision: 7582 $");
  script_cve_id("CVE-2015-1648");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 13:56:51 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2015-04-15 08:59:36 +0530 (Wed, 15 Apr 2015)");
  script_name("Microsoft Windows .NET Framework Information Disclosure Vulnerability (3048010)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-041.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaw exists when ASP.NET improperly
  handles certain requests on systems that have custom error messages disabled.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to view parts of a web configuration file, which could expose
  sensitive information.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft .NET Framework 4
  Microsoft .NET Framework 3.5
  Microsoft .NET Framework 2.0
  Microsoft .NET Framework 1.1
  Microsoft .NET Framework 3.5.1
  Microsoft .NET Framework 4.5, 4.5.1, and 4.5.2"); 

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS15-041");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3048010");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS15-041");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
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
sysVer = "";

## Check for OS and Service Pack
if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2, win7x64:2, win2008:3,
   win2008r2:2, win8:1, win8x64:1, win8_1:1, win8_1x64:1, win2012:1, win2012R2:1) <= 0){
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
    ## Get version from System.Web.dll file
    dllVer = fetch_file_version(sysPath:path, file_name:"System.Web.dll");
    if(dllVer)
    {
      ## .NET Framework 1.1 Service Pack 1 on x86-based versions of Windows Server 2003 Service Pack 2
      if((hotfix_check_sp(win2003:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"1.1.4322.2000", test_version2:"1.1.4322.2514")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Server 2003
      if((hotfix_check_sp(win2003:3, win2003x64:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.3000", test_version2:"2.0.50727.3667")||
          version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8655")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 2.0 Service Pack 2 on Windows Vista Service Pack 2 and Windows Server 2008 Service Pack 2
      if((hotfix_check_sp(winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.4000", test_version2:"2.0.50727.4256")||
          version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8652")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 3.5 for Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6426")||
          version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8652")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 3.5 on Windows 8.1 and Windows Server 2012 R2
      ## prasently not supporting Windows Server 2012 R2
      if((hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8652")||
          version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8014")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 3.5.1 for Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5490")||
          version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8652")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 4 on  Windows Server 2003, Windows Vista,
      ## Windows Server 2008, Windows 7, and Windows Server 2008 R2
      if((hotfix_check_sp(win2003:3, winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2) > 0) &&
          (version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1030")||
           version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2055")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 4.5.1 for Windows Vista Service Pack 2, Windows Server 2008 Service Pack 2
      ## Windows 7 Service Pack 1, and Windows Server 2008 R2 Service Pack 1
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, winVista:3, win2008:3) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34248") ||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36284")))
      {
        security_message(0);
        exit(0);
      }

      # .NET Framework 4.5, 4.5.1, and 4.5.2 on Windows 8, and Windows Server 2012 
      if((hotfix_check_sp(win8:1, win8x64:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34247") ||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36282")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 4.5.1 and 4.5.2 on Windows 8.1, and Windows Server 2012 R2
      ##  not supporting Windows Server 2012 R2
      if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34247")||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36282")))
      {
        security_message(0);
        exit(0);
      }

    } ## System.Web.dll - END
  }
}
