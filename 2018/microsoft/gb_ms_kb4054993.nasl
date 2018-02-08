###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_kb4054993.nasl 8699 2018-02-07 08:01:50Z asteins $
#
# Microsoft .NET Framework 4.5.2 Multiple Vulnerabilities (KB4054993)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812626");
  script_version("$Revision: 8699 $");
  script_cve_id("CVE-2018-0764", "CVE-2018-0786");
  script_bugtraq_id(102387, 102380);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-07 09:01:50 +0100 (Wed, 07 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-01-10 14:26:54 +0530 (Wed, 10 Jan 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft .NET Framework 4.5.2 Multiple Vulnerabilities (KB4054993)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4054993");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and
  check appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An error when .NET, and .NET core, improperly process XML documents.

  - An error when Microsoft .NET Framework (and .NET Core) components do not
    completely validate certificates.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions and conduct a denial-of-service
  condition.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft .NET Framework 4.5.2 on Windows Server 2012 R2 and Windows 8.1");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://support.microsoft.com/en-us/help/4054993");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/help/4054993");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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
dotPath = "";
sysdllVer = "";

if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) <= 0){
  exit(0);
}

key = "SOFTWARE\Microsoft\ASP.NET\";
if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item (registry_enum_keys(key:key))
{
  path = registry_get_sz(key:key + item, item:"Path");
  if(path && "\Microsoft.NET\Framework" >< path)
  {
    dllVer = fetch_file_version(sysPath:path, file_name:"System.Xml.dll");
    if(dllVer)
    {
      if(version_in_range(version:dllVer, test_version:"4.0.30319.30000", test_version2:"4.0.30319.36426"))
      {
        report = report_fixed_ver(file_checked:path + "\system.xml.dll",
                 file_version:dllVer, vulnerable_range:"4.0.30319.30000 - 4.0.30319.36426");
        security_message(data:report);
        exit(0);
      }
    }
  }
}
exit(0);
