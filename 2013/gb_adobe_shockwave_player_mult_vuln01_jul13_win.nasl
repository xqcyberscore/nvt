###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_shockwave_player_mult_vuln01_jul13_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Adobe Shockwave Player Multiple Vulnerabilities-01 July13 (Windows)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "
  Impact Level: System/Application";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803834");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-3348");
  script_bugtraq_id(61040);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-07-25 17:45:29 +0530 (Thu, 25 Jul 2013)");
  script_name("Adobe Shockwave Player Multiple Vulnerabilities-01 July13 (Windows)");

  tag_summary =
"This host is installed with Adobe Shockwave player and is prone to
multiple vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to an error when parsing dir files";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary
code on the target system and corrupt system memory.";

  tag_affected =
"Adobe Shockwave Player before 12.0.3.133 on Windows";

  tag_solution =
"Upgrade to version 12.0.3.133 or later,
For updates refer to http://get.adobe.com/shockwave";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/53894");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb13-18.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_adobe_shockwave_player_detect.nasl");
  script_mandatory_keys("Adobe/ShockwavePlayer/Ver");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
playerVer = "";

# Check for Adobe Shockwave Player Version
playerVer = get_kb_item("Adobe/ShockwavePlayer/Ver");
if(playerVer != NULL)
{
  if(version_is_less(version:playerVer, test_version:"12.0.3.133"))
  {
    security_message(0);
    exit(0);
  }
}
