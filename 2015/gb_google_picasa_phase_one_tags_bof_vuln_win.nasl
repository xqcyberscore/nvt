###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_google_picasa_phase_one_tags_bof_vuln_win.nasl 6254 2017-05-31 09:04:18Z teissa $
#
# Google Picasa 'Phase One Tags' Buffer Overflow Vulnerability (Windows)
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
CPE = "cpe:/a:google:picasa";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806628");
  script_version("$Revision: 6254 $");
  script_cve_id("CVE-2015-8096");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-31 11:04:18 +0200 (Wed, 31 May 2017) $");
  script_tag(name:"creation_date", value:"2015-11-26 12:49:36 +0530 (Thu, 26 Nov 2015)");
  script_name("Google Picasa 'Phase One Tags' Buffer Overflow Vulnerability (Windows)");

  script_tag(name: "summary" , value:"This host is installed with Google Picasa
  and is prone to buffer overflow vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw is due to an integer overflow
  error when processing data related to phase one 0x412 tag.");

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.

  Impact Level: System/Application");

  script_tag(name: "affected" , value: "Google Picasa versions 3.9.140 build 239
  and Build 248");

  script_tag(name: "solution" , value: "Upgrade to Google Picasa version 3.9.141
  build 259 or later. For updates refer to http://picasa.google.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2015-3");
  script_xref(name : "URL" , value : "https://packetstormsecurity.com/files/134084");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/536761/100/0/threaded");

  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_google_picasa_detect_win.nasl");
  script_mandatory_keys("Google/Picasa/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
picVer = "";

## Get version
if(!picVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Check for Google Picasa Version 3.9.140 build 239 and Build 248
if(version_is_equal(version:picVer, test_version:"3.9.140.239")||
   version_is_equal(version:picVer, test_version:"3.9.140.248"))
{
  report = 'Installed Version: ' + picVer + '\n' +
           'Fixed Version:     3.9.141 build 259  \n';
  security_message(data:report);
  exit(0);
}
