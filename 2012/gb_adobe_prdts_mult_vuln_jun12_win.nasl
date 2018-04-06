###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_prdts_mult_vuln_jun12_win.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities June-2012 (Windows)
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:adobe:flash_player";

tag_impact = "Successful exploitation could allow attackers to bypass certain security
  restrictions, execute arbitrary code in the context of the browser or cause
  a denial of service (memory corruption) via unspecified vectors.
  Impact Level: System/Application";
tag_affected = "Adobe Flash Player version before 10.3.183.20 and 11.x through 11.2.202.235
  on Windows.";
tag_insight = "Multiple errors are caused,

  - When parsing ActionScript.

  - Within NPSWF32.dll when parsing certain tags.

  - In the 'SoundMixer.computeSpectrum()' method, which can be exploited to
    bypass the same-origin policy.

  - In the installer allows planting a binary file.";
tag_solution = "Update to Adobe Flash Player version 10.3.183.20 or 11.3.300.257 or later,
  For the updates refer, http://get.adobe.com/flashplayer";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802871");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-2034", "CVE-2012-2035", "CVE-2012-2036", "CVE-2012-2037",
                "CVE-2012-2039", "CVE-2012-2038", "CVE-2012-2040");
  script_bugtraq_id(53887);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-06-20 10:16:16 +0530 (Wed, 20 Jun 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities June-2012 (Windows)");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/49388");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1027139");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-14.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
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

# Grep for version < 10.3.183.20 or <= 11.2.202.235
if( version_is_less( version:vers, test_version:"10.3.183.20" ) ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.2.202.235" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.3.183.20 or 11.3.300.257", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );