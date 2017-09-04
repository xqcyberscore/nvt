###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_office_ms16-107-2.nasl 6970 2017-08-21 06:22:17Z asteins $
#
# Microsoft Office 2013 APP-V ASLR Bypass Vulnerability (3118268)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112000");
  script_version("$Revision: 6970 $");
  script_cve_id("CVE-2016-0137");
  script_bugtraq_id(92785);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-08-21 08:22:17 +0200 (Mon, 21 Aug 2017) $");
  script_tag(name:"creation_date", value:"2017-08-18 14:45:19 +0200 (Fri, 18 Aug 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office 2013 APP-V ASLR Bypass Vulnerability (3118268)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-107.

  This NVT has been replaced by NVT 'Microsoft Office Suite Remote Code Execution Vulnerabilities (3185852)' (1.3.6.1.4.1.25623.1.0.807361).");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check if an
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"An information disclosure vulnerability exists in the way
  that the Click-to-Run (C2R) components handle objects in memory,
  which could lead to an Address Space Layout Randomization (ASLR) bypass.");

  script_tag(name:"impact", value:"Successful exploitation could allow
  remote code execution if a user opens a specially crafted Microsoft Office file.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft Office 2013 Service Pack 1");

  script_tag(name:"solution", value:"Run Windows Update and update the
  listed hotfixes or download and update mentioned hotfixes in the advisory
  from the below link,
  https://technet.microsoft.com/library/security/MS16-107");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name: "URL", value: "https://support.microsoft.com/en-us/help/3118268");
  script_xref(name: "URL", value: "https://technet.microsoft.com/library/security/MS16-107");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver");
  script_require_ports(139, 445);

  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}
exit(66); # this NVT is deprecated since it has been covered already by gb_ms_office-ms16-107.nasl

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

## Variable initialization
offVer = "";
offPath = "";
offexeVer = "";

## MS Office
offVer = get_kb_item("MS/Office/Ver");
if(!offVer){
  exit(0);
}

## Get Office File Path
path = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                       item:"CommonFilesDir");
if(!path){
  exit(0);
}

##Check for vuln version
if(offVer =~ "^15\..*")
{
  ## Get Version from Mso.dll
  offPath = path + "\Microsoft Shared\Office15";
  offexeVer = fetch_file_version(sysPath:offPath, file_name:"Mso.dll");
  if(offexeVer)
  {
    if(offexeVer =~ "^(15)"){
      Vulnerable_range3  =  "15 - 15.0.4859.0999";
    }
    ## Check for mso.dll version
    if(version_in_range(version:offexeVer, test_version:"15.0", test_version2:"15.0.4859.0999"))
    {
      report = 'File checked:     ' + offPath + "\Mso.dll" + '\n' +
               'File version:     ' + offexeVer  + '\n' +
               'Vulnerable range: ' + Vulnerable_range3 + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}
