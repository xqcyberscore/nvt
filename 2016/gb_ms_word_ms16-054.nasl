###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_word_ms16-054.nasl 5580 2017-03-15 10:00:34Z teissa $
#
# Microsoft Office Word Multiple Remote Code Execution Vulnerabilities (3155544)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807821");
  script_version("$Revision: 5580 $");
  script_cve_id("CVE-2016-0198", "CVE-2016-0183");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-03-15 11:00:34 +0100 (Wed, 15 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-05-11 12:38:06 +0530 (Wed, 11 May 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Word Multiple Remote Code Execution Vulnerabilities (3155544)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS16-054");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"Multiple errors are due to,
  - An error as windows font library improperly handles specially crafted embedded
    fonts.
  - Multiple memory corruption errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow an
  attacker to execute arbitrary code on the affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"
  Microsoft Word 2007 Service Pack 3 and prior,
  Microsoft Word 2010 Service Pack 2 and prior,
  Microsoft Word 2013 Service Pack 1 and prior,
  Microsoft Word 2016 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  below link,
  https://technet.microsoft.com/library/security/MS16-054");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3115116");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3115123");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3115025");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3115094");
  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3155544");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/library/security/MS16-054");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}


include("version_func.inc");

## variable Initialization
winwordVer = "";

##word 2007, 2010, 2013, 2016
exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer && exeVer =~ "^(12|14|15|16).*")
{
  if(exeVer =~ "^(12)"){
    Vulnerable_range  =  "12 - 12.0.6748.4999";
  }
  else if(exeVer =~ "^(14)"){
    Vulnerable_range  =  "14 - 14.0.7169.4999";
  }
  else if(exeVer =~ "^(15)"){
    Vulnerable_range  =  "15 - 15.0.4823.0999";
  }
  else if(exeVer =~ "^(16)"){
    Vulnerable_range  =  "16 - 16.0.4378.1000";
  }

  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6748.4999") ||
     version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7169.4999") ||
     version_in_range(version:exeVer, test_version:"15.0", test_version2:"15.0.4823.0999") ||
     version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.4378.1000"))
  {
     report = 'File checked:     ' + exePath + "winword.exe"  + '\n' +
              'File version:     ' + exeVer  + '\n' +
              'Vulnerable range: ' + Vulnerable_range + '\n' ;
     security_message(data:report);
     exit(0);
  }
}
