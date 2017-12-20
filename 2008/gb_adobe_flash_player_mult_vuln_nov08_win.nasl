###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_nov08_win.nasl 8178 2017-12-19 13:42:38Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities - Nov08 (Windows)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:adobe:flash_player";

tag_impact = "Successful attack could allow malicious people to bypass certain
  security restrictions or manipulate certain data.
  Impact Level: Application";
tag_affected = "Adobe Flash Player 9.0.124.0 and earlier on Windows.";
tag_insight = "Multiple flaws are reported in Adobe Flash Player, for more information
  refer,
  http://www.adobe.com/support/security/bulletins/apsb08-22.html
  http://www.adobe.com/support/security/bulletins/apsb08-20.html";
tag_solution = "Upgrade to Adobe Flash Player 9.0.151.0 or 10.0.12.36,
  http://www.adobe.com/downloads/";
tag_summary = "This host has Adobe Flash Player installed and is prone to
  multiple security bypass vulnerabilities.";

if(description)
{
  script_id(800054);
  script_version("$Revision: 8178 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 14:42:38 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2008-11-12 16:32:06 +0100 (Wed, 12 Nov 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-4818", "CVE-2008-4819", "CVE-2008-4820", "CVE-2008-4821",
                "CVE-2008-4822", "CVE-2008-4823", "CVE-2008-4824", "CVE-2008-5361",
                "CVE-2008-5362", "CVE-2008-5363");
  script_bugtraq_id(32129);
  script_name("Adobe Flash Player Multiple Vulnerabilities - Nov08 (Windows)");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb08-20.html");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb08-22.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

# Check for version 9.0.124.0 and prior
if( version_is_less_equal( version:vers, test_version:"9.0.124.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.0.124.0", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );