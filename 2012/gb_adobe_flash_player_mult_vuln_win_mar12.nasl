###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_flash_player_mult_vuln_win_mar12.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Adobe Flash Player Multiple Vulnerabilities (Windows) - Mar12
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

tag_impact = "Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the affected
  application or cause a denial of service condition.
  Impact Level: System/Application";
tag_affected = "Adobe Flash Player version before 10.3.183.16 on Windows
  Adobe Flash Player version 11.x before 11.1.102.63 on Windows";
tag_insight = "The flaws are due to an Integer errors and Unspecified error in Matrix3D
  component.";
tag_solution = "Upgrade to Adobe Flash Player version 10.3.183.16 or 11.1.102.63 or later,
  For updates refer to http://www.adobe.com/downloads/";
tag_summary = "This host is installed with Adobe Flash Player and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802811");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0769", "CVE-2012-0768");
  script_bugtraq_id(52299, 52297);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-12 18:30:17 +0530 (Mon, 12 Mar 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities (Windows) - Mar12");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/48281/");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-05.html");

  script_tag(name:"qod_type", value:"registry");
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
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Check for Adobe Flash Player versions before 10.3.183.16 and 11.1.102.63
if( version_is_less( version:vers, test_version:"10.3.183.16" ) ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.1.102.62" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.3.183.16 or 11.1.102.63", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );