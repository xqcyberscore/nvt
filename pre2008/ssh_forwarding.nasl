# OpenVAS Vulnerability Test
# $Id: ssh_forwarding.nasl 13568 2019-02-11 10:22:27Z cfischer $
# Description: OpenSSH Client Unauthorized Remote Forwarding
#
# Authors:
# Xue Yong Zhi<xueyong@udel.edu>
#
# Copyright:
# Copyright (C) 2003 Xue Yong Zhi
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
#

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11343");
  script_version("$Revision: 13568 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:22:27 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(1949);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2000-1169");
  script_name("OpenSSH Client Unauthorized Remote Forwarding");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("This script is Copyright (C) 2003 Xue Yong Zhi");
  script_family("Gain a shell remotely");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("openssh/detected");

  script_tag(name:"solution", value:"Patch and new version are available from OpenSSH.");

  script_tag(name:"summary", value:"You are running OpenSSH SSH client before 2.3.0.");

  script_tag(name:"insight", value:"This version  does not properly disable X11 or agent forwarding,
  which could allow a malicious SSH server to gain access to the X11 display and sniff X11 events,
  or gain access to the ssh-agent.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

banner = get_ssh_server_banner( port:port );
if ( ! banner )
  exit(0);

# Looking for OpenSSH product version number < 2.3
if(ereg(pattern:".*openssh[_-](1|2\.[0-2])\..*",string:tolower(banner)))
  security_message(port:port);
