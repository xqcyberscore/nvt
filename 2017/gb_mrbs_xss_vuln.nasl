###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mrbs_xss_vuln.nasl 7862 2017-11-22 10:11:26Z cfischer $
#
# Meeting Room Booking System  Multiple Vulnerabilities
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:john_beranek:meeting_room_booking_system";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107264");
  script_version("$Revision: 7862 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-22 11:11:26 +0100 (Wed, 22 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-21 07:28:01 +0200 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Meeting Room Booking System Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_mrbs_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MRBS/installed");

  script_xref(name:"URL", value:"https://www.cert-bund.de/advisoryshort/CB-K17-1995");

  tag_impact = "An attacker may leverage this issue to execute arbitrary script code in the browser
  of an unsuspecting user in the context of the affected site. This may let the 
  attacker steal cookie-based authentication credentials and launch other attacks.

  Impact Level: Application.";

  tag_affected = "Meeting Room Booking System prior to 1.7.0";

  tag_solution = "Upgrade to Meeting Room Booking System 1.7.0 or later.

  For updates refer to http://mrbs.sourceforge.net/download.php";

  tag_summary = "This host is installed with Meeting Room Booking System and is
  prone to multiple vulnerabilities.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"1.7.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.7.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
