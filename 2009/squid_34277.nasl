###############################################################################
# OpenVAS Vulnerability Test
# $Id: squid_34277.nasl 6891 2017-08-10 12:44:59Z cfischer $
#
# Squid Proxy Cache ICAP Adaptation Denial of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:squid-cache:squid";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100084");
  script_version("$Revision: 6891 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-10 14:44:59 +0200 (Thu, 10 Aug 2017) $");
  script_tag(name:"creation_date", value:"2009-03-28 19:13:00 +0100 (Sat, 28 Mar 2009)");
  script_bugtraq_id(34277);
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_name("Squid Proxy Cache ICAP Adaptation Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("secpod_squid_detect.nasl");
  script_require_ports("Services/http_proxy", 3128, "Services/www", 8080);
  script_mandatory_keys("squid_proxy_server/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34277");
  script_xref(name:"URL", value:"http://www.squid-cache.org/");

  tag_summary = "According to its version number, the remote version of Squid
  is prone to a to a remote denial-of-service vulnerability because
  the proxy server fails to adequately bounds-check user-supplied data
  before copying it to an insufficiently sized buffer.";

  tag_impact = "Successfully exploiting this issue allows remote attackers to
  consume excessive memory, resulting in a denial-of-service condition.

  Note that to exploit this issue, an attacker must be a legitimate
  client user of the proxy.";

  tag_affected = "The Squid 3.x branch is vulnerable.";

  tag_solution = "Upgrade to newer version if available.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3", test_version2:"3.1.5" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.1.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
