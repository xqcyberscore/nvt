###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apple_itunes_bof_vuln.nasl 8169 2017-12-19 08:42:31Z cfischer $
#
# Apple iTunes Malformed .mov File Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apple:itunes";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800318");
  script_version("$Revision: 8169 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-19 09:42:31 +0100 (Tue, 19 Dec 2017) $");
  script_tag(name:"creation_date", value:"2008-12-18 14:07:48 +0100 (Thu, 18 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-5406");
  script_bugtraq_id(32540);
  script_name("Apple iTunes Malformed .mov File Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_apple_itunes_detection_win_900123.nasl");
  script_mandatory_keys("iTunes/Win/Installed");

  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/7296");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/46984");

  tag_impact = "Successful exploitation could allow the attacker execution of arbitrary codes
  in the context of the affected application and can perform denial of service.

  Impact Level: Application";

  tag_affected = "Apple iTunes version 8.0.2.20 on Windows.";

  tag_insight = "The flaw is due to a failure in handling long arguments on a .mov file.";

  tag_solution = "Upgrade to Apple iTunes version 9.1.1 or later,
  For updates refer to http://www.apple.com/";

  tag_summary = "This host has iTunes installed, which is prone to Buffer Overflow
  Vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
vers = infos['version'];
path = infos['location'];

if( vers =~ "^8\.0\.2\.20$" ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.1.1", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );