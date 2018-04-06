###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_flash_player_mult_vuln_win_feb12.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities (Windows) - Feb12
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the affected application or cause a denial of
  service condition.
  Impact Level: Application.";
tag_affected = "Adobe Flash Player version before 10.3.183.15
  Adobe Flash Player version 11.x through 11.1.102.55 and prior on Windows";
tag_insight = "Flaws are due to

  - A memory corruption error in ActiveX control.

  - A type confusion memory corruption error.

  - An unspecified error related to MP4 parsing.

  - Many unspecified erros which allows to bypass certain security
    restrictions.

  - Improper validation of user supplied input which allows attackers
    to execute arbitrary HTML and script code in a user's browser session";
tag_solution = "Upgrade to Adobe Flash Player version 11.1.102.62 or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802803");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0751", "CVE-2012-0752", "CVE-2012-0753", "CVE-2012-0754",
                "CVE-2012-0757", "CVE-2012-0756", "CVE-2012-0767");
  script_bugtraq_id(52037, 52032, 52033, 52034, 51999, 52036, 52040);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-22 11:17:41 +0530 (Wed, 22 Feb 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Windows) - Feb12");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48033");
  script_xref(name : "URL" , value : "http://securitytracker.com/id/1026694");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/48033");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-03.html");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
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

## Check for Adobe Flash Player versions 11.1.102.55 and prior
if( version_is_less( version:vers, test_version:"10.3.183.15" ) ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.1.102.55" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"11.1.102.62", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );