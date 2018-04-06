###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_microsoft_security_advisory_2960358.nasl 9354 2018-04-06 07:15:32Z cfischer $
#
# Microsoft .NET Framework 'RC4' Information Disclosure Vulnerability (2960358)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804587");
  script_version("$Revision: 9354 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:15:32 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-05-15 15:17:33 +0530 (Thu, 15 May 2014)");
  script_name("Microsoft .NET Framework 'RC4' Information Disclosure Vulnerability (2960358)");

  tag_summary =
"This host is missing an important security update according to
Microsoft Security Advisory 2960358.";

  tag_vuldetect =
"Get the vulnerable file version and check appropriate patch is applied
or not.";

  tag_insight =
"The flaw is due to the RC4 encryption algorithm is used in Transport
Layer Security (TLS).";

  tag_impact =
"Successful exploitation could allow an attacker to perform man-in-the-middle
attacks and recover plaintext from encrypted sessions.

Impact Level: Application";

  tag_affected =
"Microsoft .NET Framework 3.5, 3.5.1, 4.0 and 4.5 and 4.5.X";

  tag_solution =
"Run Windows Update and update the listed hotfixes or download and
update mentioned hotfixes in the advisory from the below link,
For updates refer to https://technet.microsoft.com/en-us/library/security/2960358.aspx";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "https://support.microsoft.com/kb/2960358");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/2960358.aspx");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows");
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
if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8:1,
                   win8_1:1, win8_1x64:1, win2012:1) <= 0){
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
    ## Get version from system.dll file
    dllVer = fetch_file_version(sysPath:path, file_name:"system.dll");
    if(dllVer)
    {
     ## .NET Framework 4.5.1 and 4.5.2 on Windows 8.1, and Windows Server 2012 R2
     ## Currently not supporting for Windows Server 2012 R2
     if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
       (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34110")||
        version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36117")))
      {
        security_message(0);
        exit(0);
      }

      ## NET Framework 4.5.1 and 4.5.2 on Windows 8, and Windows Server 2012
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34110")||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36112")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 4.5.1 on Windows 7 Service Pack 1, Windows Server 2008 R2 Service Pack 1
      ## .NET Framework 4.5.2 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      ##  No file info is there
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"4.0.30319.34000", test_version2:"4.0.30319.34113")||
          version_in_range(version:dllVer, test_version:"4.0.30319.36000", test_version2:"4.0.30319.36116")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 4 on Windows 7 and Windows Server 2008 R2
      if((hotfix_check_sp(win7:2, win7x64:2, win2008:3, win2008r2:2) > 0) &&
        (version_in_range(version:dllVer, test_version:"4.0.30319.1000", test_version2:"4.0.30319.1023")||
         version_in_range(version:dllVer, test_version:"4.0.30319.2000", test_version2:"4.0.30319.2037")))
      {
        security_message(0);
        exit(0);
      }

      ##.NET Framework 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
      if((hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.5400", test_version2:"2.0.50727.5483")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7057")))
      {
        security_message(0);
        exit(0);
      }

      ##.NET Framework 3.5 on Windows 8 and Windows Server 2012
      if((hotfix_check_sp(win8:1, win2012:1) > 0) &&
         (version_in_range(version:dllVer, test_version:"2.0.50727.6000", test_version2:"2.0.50727.6416")||
          version_in_range(version:dllVer, test_version:"2.0.50727.7000", test_version2:"2.0.50727.7057")))
      {
        security_message(0);
        exit(0);
      }

      ## .NET Framework 3.5 on Windows 8.1 and Windows Server 2012 R2
      ## Currently not supporting for Windows Server 2012 R2
      if((hotfix_check_sp(win8_1:1, win8_1x64:1) > 0) &&
       (version_in_range(version:dllVer, test_version:"2.0.50727.8000", test_version2:"2.0.50727.8003")||
        version_in_range(version:dllVer, test_version:"2.0.50727.8600", test_version2:"2.0.50727.8606")))
      {
        security_message(0);
        exit(0);
      }
    }
  }
}
