###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_mult_vuln_aug13_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# RealNetworks RealPlayer Multiple Vulnerabilities August13 (Windows)
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803841");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2013-4973", "CVE-2013-4974");
  script_bugtraq_id(61989, 61990);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-08-29 10:15:44 +0530 (Thu, 29 Aug 2013)");
  script_name("RealNetworks RealPlayer Multiple Vulnerabilities August13 (Windows)");

  tag_summary =
"The host is installed with RealPlayer and is prone to multiple vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaws are due to errors when handling filenames in RMP and when parsing
RealMedia files.";

  tag_impact =
"Successful exploitation will allow remote unauthenticated attacker to obtain
sensitive information, cause a denial of service condition, or execute
arbitrary code with the privileges of the application.";

  tag_affected =
"RealPlayer version prior to 16.0.3.51 on Windows.";

  tag_solution =
"Upgrade to version 16.0.3.51 or later,
For updates refer to http://www.real.com/player";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/54621");
  script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/246524");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/08232013_player/en");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}


include("version_func.inc");

## Variable Initialization
rpVer = "";

## Get RealPlayer version from KB
rpVer = get_kb_item("RealPlayer/Win/Ver");
if(!rpVer){
  exit(0);
}

## Check for Realplayer version <= 16.0.3.51
if(version_is_less(version:rpVer, test_version:"16.0.3.51"))
{
  security_message(0);
  exit(0);
}
