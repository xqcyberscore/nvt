# OpenVAS Vulnerability Test
# $Id: pop2_unencrypted_cleartext_logins.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: POP2 Unencrypted Cleartext Logins
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

tag_summary = "The remote host is running a POP2 daemon that allows cleartext logins over
unencrypted connections.  An attacker can uncover login names and
passwords by sniffing traffic to the POP2 daemon.";

tag_solution = "Encrypt traffic with SSL / TLS using stunnel.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.15854");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_xref(name:"OSVDB", value:"3119");

  name = "POP2 Unencrypted Cleartext Logins";
  script_name(name);


  summary = "Checks for unencrypted POP2 login capability";

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "General";
  script_family(family);

  script_dependencies("find_service.nasl", "global_settings.nasl");
  script_require_ports("Services/pop2", 109);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");

port = get_kb_item("Services/pop2");
if (!port) port = 109;
debug_print("checking if POP2 daemon on port ", port, " allows unencrypted cleartext logins.");
if (!get_port_state(port)) exit(0);
# nb: skip it if traffic is encrypted.
encaps = get_port_transport(port);
if (encaps >= ENCAPS_SSLv2) exit(0);

# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);
r = recv_line(socket:soc, length:4096);
if ( "POP" >!< r ) exit(0);

# nb: POP2 doesn't support encrypted logins so there's no need to
#     actually try to log in. [Heck, I probably don't even need to
#     establish a connection.]
security_message(port);

close(soc);
