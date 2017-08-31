###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_gom_player_dos_vuln_sep14_win.nasl 6759 2017-07-19 09:56:33Z teissa $
#
# GOM Media Player Denial of Service Vulnerability Sep14 (Windows)
#
# Authors:
# Deepmala <kdeepmala@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804903");
  script_version("$Revision: 6759 $");
  script_cve_id("CVE-2014-3899");
  script_bugtraq_id(69182);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-19 11:56:33 +0200 (Wed, 19 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-09-15 12:54:27 +0530 (Mon, 15 Sep 2014)");

  script_name("GOM Media Player Denial of Service Vulnerability Sep14 (Windows)");

  script_tag(name: "summary" , value:"The host is installed with GOM Media Player
  and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with
  the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw is due to an error
  in processing an malformed image file. resulting in a loss of availability
  for the program");

  script_tag(name: "impact" , value: "Successful exploitation will allow remote
  attackers to cause a denial of service.

  Impact Level: Application");

  script_tag(name: "affected" , value: "GOM Media Player version 2.2.51.5149
  and prior on Windows.");

  script_tag(name: "solution" , value: "Upgrade to GOM Media Player version 2.2.62.5209
  or later, For updates refer to http://www.gomlab.com/eng/");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL" , value:"http://www.xforce.iss.net/xforce/xfdb/95133");
  script_xref(name:"URL" , value:"https://cxsecurity.com/cveshow/CVE-2014-3899");
  script_xref(name:"URL" , value:"http://jvndb.jvn.jp/en/contents/2014/JVNDB-2014-000085.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
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

## Check for vulnerable version
if( version_is_less_equal(version:gomVer, test_version:"2.2.51.5149"))
{
  security_message(0);
  exit(0);
}
