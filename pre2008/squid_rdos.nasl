###############################################################################
# OpenVAS Vulnerability Test
# $Id: squid_rdos.nasl 6891 2017-08-10 12:44:59Z cfischer $
#
# Squid remote denial of service
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

#  Ref: iDEFENSE 10.11.04

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15463");
  script_version("$Revision: 6891 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-10 14:44:59 +0200 (Thu, 10 Aug 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11385);
  script_cve_id("CVE-2004-0918");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Squid remote denial of service");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  tag_summary = "The remote squid caching proxy, according to its version number, may be
  vulnerable to a remote denial of service.";

  tag_insight = "This flaw is due to an input validation error in the SNMP module.";

  tag_impact = "An attacker can exploit this flaw to crash the server with a specially
  crafted UDP packet.";

  tag_solution = "Upgrade to squid 2.5.STABLE7 or newer";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"2.0", test_version2:"2.5.STABLE6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.5.STABLE7" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
