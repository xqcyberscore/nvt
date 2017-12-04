###############################################################################
# OpenVAS Vulnerability Test
# $Id: openssh_afs.nasl 7904 2017-11-24 12:29:45Z cfischer $
#
# OpenSSH AFS/Kerberos ticket/token passing
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (C) 2002 Thomas Reinke
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10954");
  script_version("$Revision: 7904 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-24 13:29:45 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(4560);
  script_cve_id("CVE-2002-0575");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("OpenSSH AFS/Kerberos ticket/token passing");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Thomas Reinke");
  script_family("Gain a shell remotely");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");

  script_tag(name:"solution", value:"Upgrade to the latest version of OpenSSH");

  script_tag(name:"summary", value:"You are running a version of OpenSSH older than OpenSSH 3.2.1

  A buffer overflow exists in the daemon if AFS is enabled on your system, or if the options
  KerberosTgtPassing or AFSTokenPassing are enabled.  Even in this scenario, the vulnerability
  may be avoided by enabling UsePrivilegeSeparation.");

  script_tag(name:"affected", value:"Versions prior to 2.9.9 are vulnerable to a remote root
  exploit. Versions prior to 3.2.1 are vulnerable to a local root exploit.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"3.2.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.2.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
