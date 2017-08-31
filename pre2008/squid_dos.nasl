###############################################################################
# OpenVAS Vulnerability Test
# $Id: squid_dos.nasl 6898 2017-08-11 07:49:05Z cfischer $
#
# Squid Denial-of-Service Vulnerability
#
# Authors:
# Adam Baldwin <adamb@amerion.net>
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2001 Adam Baldwin
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10768");
  script_version("$Revision: 6898 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-11 09:49:05 +0200 (Fri, 11 Aug 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(3354);
  script_cve_id("CVE-2001-0843");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Squid Denial-of-Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2001 Adam Baldwin");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  tag_summary = "A problem exists in the way the remote Squid proxy server handles a
  special 'mkdir-only' PUT request, and causes denial of service to the proxy
  server.";

  tag_impact = "An attacker may use this flaw to prevent your LAN users from accessing
  the web.";

  tag_solution = "Apply the vendor released patch, for squid it is located here:
  www.squid-cache.org. You can also protect yourself by enabling access lists
  on your proxy.";

  script_tag(name:"summary", value:tag_summary);
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

# checking for the Version < =2.4
if( "2.3" >< vers && ( "STABLE1" >< vers || "STABLE3" >< vers ||
    "STABLE4" >< vers || "STABLE5" >< vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

#CHECK VERSION 2.4
if( "2.4" >< vers && ( "STABLE1" >< vers || "PRE-STABLE2" >< vers ||
   "PRE-STABLE" >< vers || "DEVEL4" >< vers || "DEVEL2" >< vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
