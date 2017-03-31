###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ms_onenote_ms16-070.nasl 3543 2016-06-17 06:11:56Z antu123 $
#
# Microsoft OneNote Remote Code Execution Vulnerability (3114862)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:microsoft:onenote";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808229");
  script_version("$Revision: 3543 $");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2016-06-17 08:11:56 +0200 (Fri, 17 Jun 2016) $");
  script_tag(name:"creation_date", value:"2016-06-16 11:22:43 +0530 (Thu, 16 Jun 2016)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft OneNote Remote Code Execution Vulnerability (3114862)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS16-070.");

  script_tag(name:"vuldetect", value:"Get the vulnerable file version and check
  appropriate patch is applied or not.");

  script_tag(name:"insight", value:"The flaws exists when a user opens a specially 
  crafted Office file.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Microsoft OneNote 2016");

  script_tag(name:"solution", value:"Run Windows Update and update the listed
  hotfixes or download and update mentioned hotfixes in the advisory from the
  below link, https://technet.microsoft.com/en-us/security/bulletin/ms16-070");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://support.microsoft.com/en-us/kb/3114862");
  script_xref(name : "URL" , value : "https://technet.microsoft.com/en-us/library/security/MS16-070");

  script_summary("Check for the version of 'onenote.exe' file");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_onenote_detect.nasl");
  script_mandatory_keys("MS/Office/OneNote/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

# Variable Initialization
exeVer = "";
notePath = "";

## Get 'OneNote.exe' Version
exeVer = get_app_version(cpe:CPE);
if(!exeVer){
  exit(0);
}

## Get location
notePath = get_app_location(cpe:CPE);
if(!notePath){
  notePath =  "Unable to fetch full installtion path";
}

if(exeVer && exeVer =~ "^(16).*")
{

  if(version_in_range(version:exeVer, test_version:"16.0", test_version2:"16.0.4366.999"))
  {
     report = 'File checked:     ' + notePath + 'onenote.exe'  + '\n' +
              'File version:     ' + exeVer  + '\n' +
              'Vulnerable range:   16.0 - 16.0.4366.999' + '\n' ;
     security_message(data:report);
     exit(0);
  }
}
