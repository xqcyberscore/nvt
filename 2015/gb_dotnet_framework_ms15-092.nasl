###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnet_framework_ms15-092.nasl 10017 2018-05-30 07:17:29Z cfischer $
#
# Microsoft .NET Framework Privilege Elevation Vulnerability (3086251)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.805952");
  script_version("$Revision: 10017 $");
  script_cve_id("CVE-2015-2479", "CVE-2015-2480", "CVE-2015-2481");
  script_bugtraq_id(76268, 76269, 76270);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 09:17:29 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2015-08-12 12:08:40 +0530 (Wed, 12 Aug 2015)");
  script_name("Microsoft .NET Framework Privilege Elevation Vulnerability (3086251)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS15-092.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Flaw exists due to error in RyuJIT compiler
  which improperly optimizes certain parameters resulting in a code generation
  error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to take complete control of an affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft .NET Framework 4.6");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,

  https://technet.microsoft.com/library/security/MS15-092");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3083185");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3083184");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3083186");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS15-092");

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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2,
                   win8:1, win8x64:1, win8_1:1, win8_1x64:1, win2012:1,
                   win2012R2:1, win10:1, win10x64:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full";
if(!registry_key_exists(key:key)){
  exit(0);
}

version = registry_get_sz(key:key, item:"Version");
if(!version){
  exit(0);
}

if(version =~ "^4.6.")
{
  path = registry_get_sz(key:key, item:"InstallPath");
  if(path && "Microsoft.NET" >< path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"mscorlib.dll");
    if(dllVer)
    {
      ## Windows Vista, Windows Server 2008, Windows 7 and Windows Server 2008 R2
      if((hotfix_check_sp(winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_is_less(version:dllVer, test_version:"4.6.100.0")))
      {
        security_message(0);
        exit(0);
      }

      ##Windows 8, Windows Server 2012, Windows 8.1 , Windows Server 2012 R2 and Windows 10
      if((hotfix_check_sp(win8:1, win8x64:1, win2012:1, win8_1:1, win8_1x64:1,
          win2012R2:1, win10:1, win10x64:1) > 0) &&
        (version_is_less(version:dllVer, test_version:"4.6.96.0")))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
