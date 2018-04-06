# OpenVAS Vulnerability Test
# $Id: egd_detect.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: EGD detection
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

tag_summary = "A random number generator is listening on the remote port.

Description :

The Entropy Gathering Daemon is running on the remote host.
EGD is a user space random generator for operating systems 
that lack /dev/random";

tag_solution = "If this service is not needed, disable it or filter incoming traffic
to this port.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18393");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("EGD detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 script_family( "Service detection");
 script_require_ports("Services/unknown", 8000);
 script_dependencies("find_service1.nasl", "find_service2.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://egd.sourceforge.net/");
 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');

port = get_unknown_port( default:8000 );

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\0');	# get
r = recv(socket: s, length: 16);
close(s);
if (strlen(r) != 4) exit(0);
entropy = 0;
for (i = 0; i <= 3; i ++)
 entropy = (entropy << 8) | ord(r[i]);

debug_print('entropy=', entropy, '\n');

s = open_sock_tcp(port);
if (! s) exit(0);
send(socket: s, data: '\x01\x07');	# Read 7 bytes of entropy
r = recv(socket: s, length: 16);
close(s);
n = ord(r[0]);
if (strlen(r) != n + 1) exit(0);
debug_print('EGD gave ', n, 'bytes of entropy (7 requested)\n');

register_service(port: port, proto: 'egd');
log_message(port);
