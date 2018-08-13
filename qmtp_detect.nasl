# OpenVAS Vulnerability Test
# $Id: qmtp_detect.nasl 10906 2018-08-10 14:50:26Z cfischer $
# Description: QMTP
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11134");
  script_version("$Revision: 10906 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 16:50:26 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_analysis");

  script_name("QMTP Detection");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "find_service2.nasl");
  script_require_ports(209, 628);
  script_tag(name:"summary", value:"Checks for the presence of QMTP/QMQP server.");
  exit(0);
}

####

include("misc_func.inc");
include("network_func.inc");

ports = get_kb_list("Services/QMTP");
if (! ports)
  ports = make_list(209, 628);

function netstr(str)
{
  local_var	l;

  l = strlen(str);
  return strcat(l, ":", str, ",");
}

foreach port (ports) {
  if (service_is_unknown(port: port) && get_port_state(port)) {
    soc = open_sock_tcp(port);
    if (soc) {
      msg = strcat(netstr(str: "
Message-ID: <1234567890.666.openvas@example.org>
From: openvas@example.org
To: postmaster@example.com

OpenVAS is probing this server.
"),
		   netstr(str: "openvas@example.org"),
		   netstr(str: netstr(str: "postmaster@example.com")));

      # QMQP encodes the whole message once more
      if (port == 628) {
        msg = netstr(str: msg);
        srv = "QMQP";
      }
      else
        srv = "QMTP";

      send(socket: soc, data: msg);
      r = recv(socket: soc, length: 1024);
      close(soc);

      if (ereg(pattern: "^[1-9][0-9]*:[KZD]", string: r)) {
        log_message(port:port);
        register_service(port: port, proto: srv);
      }
    }
  }
}

exit(0);
