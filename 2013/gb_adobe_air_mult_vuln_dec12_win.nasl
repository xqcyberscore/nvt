###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln_dec12_win.nasl 9353 2018-04-06 07:14:20Z cfischer $
#
# Adobe Air Multiple Vulnerabilities - December12 (Windows)
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

CPE = "cpe:/a:adobe:adobe_air";

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code or denial of service.
  Impact Level: System/Application";
tag_affected = "Adobe AIR version 3.5.0.600 and earlier on Windows";
tag_insight = "Multiple unspecified errors and integer overflow exists that could lead to
  code execution.";
tag_solution = "Update to Adobe Air version 3.5.0.880 or later,
  For updates refer to http://get.adobe.com/air";
tag_summary = "This host is installed with Adobe Air and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803456");
  script_version("$Revision: 9353 $");
  script_cve_id("CVE-2012-5676", "CVE-2012-5677", "CVE-2012-5678");
  script_bugtraq_id(56892, 56896, 56898);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:14:20 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-03-28 18:27:23 +0530 (Thu, 28 Mar 2013)");
  script_name("Adobe Air Multiple Vulnerabilities - December12 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/51560");
  script_xref(name : "URL" , value : "http://securitytracker.com/id?1027854");
  script_xref(name : "URL" , value : "http://technet.microsoft.com/en-us/security/advisory/2755801");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-27.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

# Grep for version less than 3.5.0.880
if( version_is_less( version:vers, test_version:"3.5.0.880" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.5.0.880", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );