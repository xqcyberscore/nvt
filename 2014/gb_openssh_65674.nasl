###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssh_65674.nasl 7904 2017-11-24 12:29:45Z cfischer $
#
# OpenSSH 'ssh-keysign.c' Local Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105002");
  script_bugtraq_id(65674);
  script_cve_id("CVE-2011-4327");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 7904 $");
  script_name("OpenSSH 'ssh-keysign.c' Local Information Disclosure Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2017-11-24 13:29:45 +0100 (Fri, 24 Nov 2017) $");
  script_tag(name:"creation_date", value:"2014-04-09 12:29:38 +0200 (Wed, 09 Apr 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65674");
  script_xref(name:"URL", value:"http://www.openssh.com");
  script_xref(name:"URL", value:"http://www.openssh.com/txt/portable-keysign-rand-helper.adv");

  tag_insight = "ssh-keysign.c in ssh-keysign in OpenSSH before 5.8p2 on
  certain platforms executes ssh-rand-helper with unintended open file
  descriptors, which allows local users to obtain sensitive key information
  via the ptrace system call.";

  tag_impact = "Local attackers can exploit this issue to obtain sensitive
  information. Information obtained may lead to further attacks.";

  tag_affected = "Versions prior to OpenSSH 5.8p2 are vulnerable.";

  tag_summary = "OpenSSH is prone to a local information-disclosure vulnerability.";

  tag_solution = "Updates are available.";

  tag_vuldetect = "Check the version.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"vuldetect", value:tag_vuldetect);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.8p2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.8p2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
