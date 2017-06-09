###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_bof_vuln_win_dec13.nasl 6115 2017-05-12 09:03:25Z teissa $
#
# RealNetworks RealPlayer Buffer Overflow Vulnerability Dec13 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:realnetworks:realplayer";
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804178";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6115 $");
  script_cve_id("CVE-2013-6877", "CVE-2013-7260");
  script_bugtraq_id(64398, 64695);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
  script_tag(name:"creation_date", value:"2013-12-26 11:34:28 +0530 (Thu, 26 Dec 2013)");
  script_name("RealNetworks RealPlayer Buffer Overflow Vulnerability Dec13 (Windows)");

  tag_summary =
"The host is installed with RealPlayer and is prone to buffer overflow
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to,
- An error in handling the 'version' and 'encoding' attributes in RMP files.
- Improper validation of user input when handling the 'trackid' attribute in
  RMP files.";

  tag_impact =
"Successful exploitation will allow remote unauthenticated attacker to execute
arbitrary code with the privileges of the application.

Impact Level: System/Application";

  tag_affected =
"RealPlayer version before 17.0.4.61 on Windows.";

  tag_solution =
"Upgrade to RealPlayer version 17.0.4.61 or later,
For updates refer to http://www.real.com/player";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/56219");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/12202013_player/en");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
rpVer = "";

## Get version
if(!rpVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

# Check for vulnerable version
if(version_is_less(version:rpVer, test_version:"17.0.4.61"))
{
  security_message(0);
  exit(0);
}
