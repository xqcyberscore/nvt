###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_notepadpp_hexeditor_rce_vuln.nasl 8588 2018-01-30 14:51:34Z asteins $
#
# Notepad++ Hex Editor Plugin Buffer Overflow Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:don_ho:notepad++";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811586");
  script_version("$Revision: 8588 $");
  script_cve_id("CVE-2017-8803");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-01-30 15:51:34 +0100 (Tue, 30 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-08-22 14:00:19 +0530 (Tue, 22 Aug 2017)");
  script_name("Notepad++ Hex Editor Plugin Buffer Overflow Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with Notepad++
  and is prone to a Buffer Overflow Vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version of Notepad++ 
  with the help of detect NVT and also get the version of Hex Editor Plugin 
  and check the versions are vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to a 'Data from Faulting 
  Address controls Code Flow' issue in Hex Editor in Notepad++.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  user-assisted attackers to execute code via a crafted file.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Notepad++ version 7.3.3 (32-bit) with 
  Hex Editor Plugin v0.9.5 on Windows.");

  script_tag(name: "solution" , value:"No solution or patch is available as of 
  30th January, 2018. Information regarding this issue will be updated once the 
  solution details are available.
  For updates refer to http://notepad-plus-plus.org");
  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name: "URL" , value : "https://github.com/wlinzi/security_advisories/tree/master/CVE-2017-8803");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_notepadpp_detect_win.nasl");
  script_mandatory_keys("Notepad++/Win/Ver");
  script_exclude_keys("Notepad++64/Win/Ver");
  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("host_details.inc");

## Variable Initialization
noteVer = "";

## Get version and installation path
noteVer = get_app_version(cpe:CPE);
notePath = get_app_location(cpe:CPE);

## Check for Notepad++ vulnerable version and installation path
if(!(noteVer == "7.3.3") || !notePath){
  exit(0);
}

## Check hexeditor vulnerable version
if(!dllVer = fetch_file_version(sysPath:notePath, file_name:"plugins\hexeditor.dll")){
  exit(0);
}

if(dllVer == "0.9.5.0")
{
  report = report_fixed_ver(installed_version: "notepad++ " + noteVer + " hexeditor " + dllVer, fixed_version: "NoneAvailable");
  security_message(data:report);
  exit(0);
}
