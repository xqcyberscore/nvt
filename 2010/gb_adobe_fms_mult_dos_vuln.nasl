###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_mult_dos_vuln.nasl 4711 2016-12-08 10:12:18Z cfi $
#
# Adobe Flash Media Server Multiple Denial of Service Vulnerabilities
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:adobe:flash_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800183");
  script_version("$Revision: 4711 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-08 11:12:18 +0100 (Thu, 08 Dec 2016) $");
  script_tag(name:"creation_date", value:"2010-11-19 15:31:49 +0100 (Fri, 19 Nov 2010)");
  script_cve_id("CVE-2010-3633", "CVE-2010-3634", "CVE-2010-3635");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Media Server Multiple Denial of Service Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_require_ports("Services/www", 1111);
  script_mandatory_keys("Adobe/FMS/installed");

  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-27.html");

  tag_impact = "Successful exploitation will let the remote unauthenticated attackers to
  run malicious code and crash the application resulting denial of service.

  Impact Level: Application";

  tag_affected = "Flash Media Server 3.0.x before 3.0.7, 3.5.x before 3.5.5
  and 4.0.x before 4.0.1";

  tag_insight = "The flaws are due to unspecified vectors. For more details please refer
  reference section.";

  tag_solution = "Update to 4.0.1 or 3.5.5 or 3.0.7 and above.
  For updates refer to http://www.adobe.com/support/security/bulletins/apsb10-27.html";

  tag_summary = "This host is running Adobe Flash Media Server and is prone to multiple
  denial of service vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Check for vulnerable versions <=4.0.0 or <=3.5.4 or <= 3.0.6
if( version_in_range( version:vers, test_version:"4.0", test_version2:"4.0.0" ) ||
    version_in_range( version:vers, test_version:"3.5", test_version2:"3.5.4" ) ||
    version_in_range( version:vers, test_version:"3.0", test_version2:"3.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.7/3.5.5/4.0.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );