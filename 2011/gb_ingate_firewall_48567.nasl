###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ingate_firewall_48567.nasl 4878 2016-12-29 18:43:19Z cfi $
#
# Ingate Firewall SIP Module Remote Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/h:ingate:ingate_firewall";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103208");
  script_version("$Revision: 4878 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 19:43:19 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)");
  script_bugtraq_id(48567);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Ingate Firewall SIP Module Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_ingate_firewall_detect.nasl");
  script_mandatory_keys("Ingate_Firewall/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48567");
  script_xref(name:"URL", value:"http://www.ingate.com/");
  script_xref(name:"URL", value:"http://www.ingate.com/Relnote.php?ver=492");

  tag_summary = "Ingate Firewall is prone to a denial-of-service vulnerability.";

  tag_impact = "An attacker can exploit this issue to cause SIP modules to reset,
  denying service to legitimate users.";

  tag_solution = "Updates are available. Please see the references for details.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_proto( cpe:CPE, port:port ) ) exit( 0 );

version = infos["version"];
proto = infos["proto"];

if( version_is_less( version:version, test_version:"4.9.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"4.9.2" );
  security_message( port:port, data:report, protocol:proto );
  exit( 0 );
}

exit( 99 );