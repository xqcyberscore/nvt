###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_adobe_prdts_code_exec_n_dos_vuln_win.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Adobe Flash Player Code Execution and DoS Vulnerabilities (Windows)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.903014");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-0772", "CVE-2012-0773", "CVE-2012-0724", "CVE-2012-0725");
  script_bugtraq_id(52748, 52916, 52914);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-30 11:21:49 +0530 (Fri, 30 Mar 2012)");
  script_name("Adobe Flash Player Code Execution and DoS Vulnerabilities (Windows)");

  tag_summary = "This host is installed with Adobe Flash Player and is prone to
code execution and denial of service vulnerabilities.";

  tag_vuldetect = "Get the installed version with the help of detect NVT and check the version
is vulnerable or not.";

  tag_insight = "The flaws are due to

 - An error within an ActiveX Control when checking the URL security domain.

 - An unspecified error within the NetStream class.";

  tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
code or cause a denial of service (memory corruption) via unknown vectors.

  Impact Level: System/Application";

  tag_affected = "Adobe Flash Player version prior to 10.3.183.18 and 11.x to 11.1.102.63
on Windows";

  tag_solution = "Update to Adobe Flash Player version 10.3.183.18 or 11.2.202.228 or later,
For updates refer to http://get.adobe.com/flashplayer";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/48623");
  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1026859");
  script_xref(name : "URL" , value : "http://www.adobe.com/support/security/bulletins/apsb12-07.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

## Grep for version < 10.3.183.18 or 11.x through 11.1.102.63
if( version_is_less( version:vers, test_version:"10.3.183.18" ) ||
    version_in_range( version:vers, test_version:"11.0", test_version2:"11.1.102.63" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.3.183.18 or 11.2.202.228", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );