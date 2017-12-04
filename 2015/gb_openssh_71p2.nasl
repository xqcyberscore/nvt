###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_71p2.nasl 7908 2017-11-24 15:00:22Z cfischer $
#
# OpenSSH Client Information Leak
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105512");
  script_cve_id("CVE-2016-0777","CVE-2016-0778");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_version("$Revision: 7908 $");
  script_name("OpenSSH Client Information Leak");
  script_tag(name:"last_modification", value:"$Date: 2017-11-24 16:00:22 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name:"creation_date", value:"2016-01-14 17:31:53 +0100 (Thu, 14 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-7.1p2");

  script_tag(name:"vuldetect", value:"Check the version from ssh-banner.");

  script_tag(name:"solution", value:"Update to 7.1p2 or newer.");

  script_tag(name:"summary", value:"The OpenSSH client code between 5.4 and 7.1p1 contains experimental support for resuming SSH-connections (roaming).
  The matching server code has never been shipped, but the client code was enabled by default and could be tricked by a malicious
  server into leaking client memory to the server, including private client user keys. The authentication of the server host key prevents exploitation
  by a man-in-the-middle, so this information leak is restricted to connections to malicious or compromised servers.");

  script_tag(name:"affected", value:"OpenSSH >= 5.4 < 7.1p2");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"5.4", test_version2:"7.1p1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.1p2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );