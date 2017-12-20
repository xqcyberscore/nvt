###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_air_mult_vuln_jun12_win.nasl 8176 2017-12-19 12:50:00Z cfischer $
#
# Adobe Air Multiple Vulnerabilities June-2012 (Windows)
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

tag_impact = "Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or cause
  a denial of service (memory corruption) via unspecified vectors.
  Impact Level: System/Application";

tag_affected = "Adobe AIR version 3.2.0.2070 and prior on Windows";
tag_insight = "Multiple errors are caused,
  - When parsing ActionScript.
  - Within NPSWF32.dll when parsing certain tags.
  - In the 'SoundMixer.computeSpectrum()' method, which can be exploited to
    bypass the same-origin policy.
  - In the installer allows planting a binary file.";
tag_solution = "Update to Adobe Air version 3.3.0.3610 or later,
  For the updates refer, http://get.adobe.com/air";
tag_summary = "This host is installed with Adobe Air and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(803813);
  script_version("$Revision: 8176 $");
  script_cve_id("CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037",
                "CVE-2012-2039", "CVE-2012-2038", "CVE-2012-2040");
  script_bugtraq_id(53887);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 13:50:00 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-07-11 15:04:41 +0530 (Thu, 11 Jul 2013)");
  script_name("Adobe Air Multiple Vulnerabilities June-2012 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49388");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027139");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
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

# Grep for version <= 3.2.0.2070
if( version_is_less_equal( version:vers, test_version:"3.2.0.2070" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.3.0.3610", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );