###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnet_framework_ms16-041.nasl 10017 2018-05-30 07:17:29Z cfischer $
#
# Microsoft .NET Framework Remote Code Execution Vulnerability (3148789)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807662");
  script_version("$Revision: 10017 $");
  script_cve_id("CVE-2016-0148");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 09:17:29 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2016-04-13 12:18:40 +0530 (Wed, 13 Apr 2016)");
  script_name("Microsoft .NET Framework Remote Code Execution Vulnerability (3148789)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-041.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Flaw exists due to improper validation of
  input before Microsoft .NET Framework loads libraries.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to take complete control of an affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft .NET Framework 4.6 and 4.6.1");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,

  https://technet.microsoft.com/library/security/MS16-041");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3143693");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-041");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(hotfix_check_sp(winVista:3, win7:2, win7x64:2, win2008:3, win2008r2:2) <= 0){
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

if(version =~ "^4\.6")
{
  dotPath = registry_get_sz(key:key, item:"InstallPath");
  if(dotPath && "Microsoft.NET" >< dotPath)
  {
    dllVer = fetch_file_version(sysPath:dotPath, file_name:"mscorlib.dll");
    if(dllVer)
    {
      ## Windows Vista, Windows Server 2008, Windows 7 and Windows Server 2008 R2
      if((hotfix_check_sp(winVista:3, win2008:3, win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_is_less(version:dllVer, test_version:"4.6.1076.0")))
      {
        report = 'File checked:     ' + dotPath + "\mscorlib.dll" + '\n' +
                 'File version:     ' + dllVer  + '\n' +
                 'Vulnerable range: ' + "Less than 4.6.1076.0" + '\n' ;
        security_message(data:report);
        exit(0);
      }
    }
  }
}
