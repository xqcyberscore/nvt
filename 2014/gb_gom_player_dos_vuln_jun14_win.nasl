###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gom_player_dos_vuln_jun14_win.nasl 6995 2017-08-23 11:52:03Z teissa $
#
# GOM Media Player Denial of Service Vulnerability Jun14 (Windows)
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
CPE = "cpe:/a:gomlab:gom_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804638");
  script_version("$Revision: 6995 $");
  script_cve_id("CVE-2014-3216");
  script_bugtraq_id(67385);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-08-23 13:52:03 +0200 (Wed, 23 Aug 2017) $");
  script_tag(name:"creation_date", value:"2014-06-13 19:29:01 +0530 (Fri, 13 Jun 2014)");
  script_name("GOM Media Player Denial of Service Vulnerability Jun14 (Windows)");

  tag_summary =
"The host is installed with GOM Media Player and is prone to denial of service
vulnerability.";

  tag_vuldetect =
"Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight =
"The flaw is due to an array indexing error within the 'gaf.ax' filter when
processing OGG files.";

  tag_impact =
"Successful exploitation will allow remote attackers to corrupt memory and
cause a denial of service or execute an arbitrary code.

Impact Level: System/Application";

  tag_affected =
"GOM Media Player version 2.2.57.5189 and before on Windows.";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/58274");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/33335");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/126548");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_gom_player_detect_win.nasl");
  script_mandatory_keys("GOM/Player/Ver/Win");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
gomVer = "";

## Get version
if(!gomVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less_equal(version:gomVer, test_version:"2.2.57.5189"))
{
  security_message(0);
  exit(0);
}
