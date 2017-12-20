###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_mult_vuln_jun13_win.nasl 8169 2017-12-19 08:42:31Z cfischer $
#
# Apple iTunes Multiple Vulnerabilities - June13 (Windows)
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

CPE = "cpe:/a:apple:itunes";

tag_impact = "Successful exploitation will allow attackers to execute arbitrary code,
  conduct Man-in-the-Middle (MitM) attack or cause heap-based buffer overflow.
  Impact Level: System/Application";

tag_affected = "Apple iTunes before 11.0.3 on Windows";
tag_insight = "Multiple flaws due to
  - Improper validation of SSL certificates.
  - Integer overflow error within the 'string.replace()' method.
  - Some vulnerabilities are due to a bundled vulnerable version of WebKit.
  - Array indexing error when handling JSArray objects.
  - Boundary error within the 'string.concat()' method.";
tag_solution = "Upgrade to version 11.0.3 or later,
  For updates refer to http://www.apple.com/itunes/download";
tag_summary = "This host is installed with Apple iTunes and is prone to
  multiple vulnerabilities.";

if(description)
{
  script_id(803806);
  script_version("$Revision: 8169 $");
  script_cve_id("CVE-2013-1014", "CVE-2013-1011", "CVE-2013-1010", "CVE-2013-1008",
                "CVE-2013-1007", "CVE-2013-1006", "CVE-2013-1005", "CVE-2013-1004",
                "CVE-2013-1003", "CVE-2013-1002", "CVE-2013-1001", "CVE-2013-1000",
                "CVE-2013-0999", "CVE-2013-0998", "CVE-2013-0997", "CVE-2013-0996",
                "CVE-2013-0995", "CVE-2013-0994", "CVE-2013-0993", "CVE-2013-0992",
                                                                   "CVE-2013-0991");
  script_bugtraq_id(59941, 59974, 59976, 59977, 59970, 59973, 59972, 59971,
                    59967, 59965, 59964, 59963, 59960, 59959, 59958, 59957,
                                         59956, 59955, 59954, 59953, 59944);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 09:42:31 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2013-06-06 13:03:34 +0530 (Thu, 06 Jun 2013)");
  script_name("Apple iTunes Multiple Vulnerabilities - June13 (Windows)");
  script_xref(name : "URL" , value : "http://support.apple.com/kb/HT5766");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/53471");
  script_xref(name : "URL" , value : "http://lists.apple.com/archives/security-announce/2013/May/msg00000.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");
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

## Check for the vulnerable version
if( version_is_less( version:vers, test_version:"11.0.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"11.0.3", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );