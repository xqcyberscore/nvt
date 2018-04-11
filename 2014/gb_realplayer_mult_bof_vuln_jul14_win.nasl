###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_realplayer_mult_bof_vuln_jul14_win.nasl 9415 2018-04-10 06:55:50Z cfischer $
#
# RealNetworks RealPlayer Multiple Buffer Overflow Vulnerabilities July14 (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:realnetworks:realplayer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804678");
  script_version("$Revision: 9415 $");
  script_cve_id("CVE-2014-3113");
  script_bugtraq_id(68442);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-10 08:55:50 +0200 (Tue, 10 Apr 2018) $");
  script_tag(name:"creation_date", value:"2014-07-14 16:18:41 +0530 (Mon, 14 Jul 2014)");
  script_name("RealNetworks RealPlayer Multiple Buffer Overflow Vulnerabilities July14 (Windows)");

  tag_summary =
"The host is installed with RealPlayer and is prone to multiple buffer overflow
vulnerabilities.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"Flaw is due to improper validation when handling corrupt index types or
incorrect media sample sizes.";

  tag_impact =
"Successful exploitation will allow remote attackers to cause a buffer
overflow, resulting in a denial of service or potentially allowing the
execution of arbitrary code.

Impact Level: System/Application";

  tag_affected =
"RealNetworks RealPlayer before version 17.0.10.8 on Windows.";

  tag_solution =
"Upgrade to RealNetworks RealPlayer version 17.0.10.8 or later.
For updates refer http://www.real.com";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/59238");
  script_xref(name : "URL" , value : "http://service.real.com/realplayer/security/06272014_player/en/");
  script_xref(name : "URL" , value : "https://fortiguard.com/zeroday/FG-VD-14-001");
  script_xref(name : "URL" , value : "https://fortiguard.com/zeroday/FG-VD-14-002");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_realplayer_detect_win.nasl");
  script_mandatory_keys("RealPlayer/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
realVer = "";

## Get version
if(!realVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:realVer, test_version:"17.0.10.8"))
{
  security_message(0);
  exit(0);
}
