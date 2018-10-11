###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_72p2.nasl 11811 2018-10-10 09:55:00Z asteins $
#
# OpenSSH <= 7.2p1 - Xauth Injection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105581");
  script_version("$Revision: 11811 $");
  script_cve_id("CVE-2016-3115");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-10 11:55:00 +0200 (Wed, 10 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-03-21 11:45:13 +0100 (Mon, 21 Mar 2016)");
  script_name("OpenSSH <= 7.2p1 - Xauth Injection");

  script_tag(name:"summary", value:"openssh xauth command injection may lead to forced-command and /bin/false bypass");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user may inject arbitrary xauth commands by sending an x11 channel request that includes a newline character in the x11 cookie. The newline acts as a command separator to the xauth binary. This attack requires the server to have 'X11Forwarding yes' enabled. Disabling it, mitigates this vector.");
  script_tag(name:"impact", value:"By injecting xauth commands one gains limited* read/write arbitrary files, information leakage or xauth-connect capabilities.");

  script_tag(name:"affected", value:"OpenSSH versions before 7.2p2");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 7.2p2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-7.2p2");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");
  script_xref(name:"URL", value:"http://www.openssh.com");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

fix = '7.2p2';

if( ! port = get_app_port( cpe:CPE ) ) exit(0);

if( ! version = get_app_version( cpe:CPE, port:port ) ) exit(0);

if( version =~ "^[0-6]\." || version =~ "^7\.[0-1]($|[^0-9])" || version =~ "7.2($|p1)" )
{
  report = report_fixed_ver(  installed_version:version, fixed_version:fix );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

