###############################################################################
# OpenVAS Vulnerability Test
# $Id: line_overflow.nasl 4750 2016-12-12 15:39:21Z cfi $
#
# Too long line
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11175");
  script_version("$Revision: 4750 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-12 16:39:21 +0100 (Mon, 12 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Too long line");
  script_category(ACT_FLOOD);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/unknown");

  tag_summary = "It was possible to kill the service by sending a single long 
  text line.";

  tag_impact = "A cracker may be able to use this flaw to crash your software
  or even execute arbitrary code on your system.";

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact" , value:tag_impact);

  exit(0);
}

include('misc_func.inc');

port = get_unknown_port( nodefault:TRUE );

line = string(crap(512), "\r\n");

s = open_sock_tcp(port);
if (s)
{
  send(socket: s, data: line);
  r = recv(socket:s, length:1); # Make sure data arrived
  close(s);
  s = open_sock_tcp(port);
  if (s) { close(s); }
  else { security_message(port); }
}

exit(0);