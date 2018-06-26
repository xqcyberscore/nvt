###############################################################################
# OpenVAS Vulnerability Test
# $Id: smtp_overflows.nasl 10317 2018-06-25 14:09:46Z cfischer $
#
# Generic SMTP overflows
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2003 Michel Arboi
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
  script_oid("1.3.6.1.4.1.25623.1.0.11772");
  script_version("$Revision: 10317 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-25 16:09:46 +0200 (Mon, 25 Jun 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Generic SMTP overflows");
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_copyright("This script is Copyright (C) 2003 Michel Arboi");
  script_family("SMTP problems");
  script_dependencies("sendmail_expn.nasl", "smtpserver_detect.nasl");
  script_exclude_keys("SMTP/wrapped");
  script_require_ports("Services/smtp", 25);

  script_tag(name:"solution", value:"Upgrade your MTA or change it.");

  script_tag(name:"summary", value:"The remote SMTP server crashes when it is send a command
  with a too long argument.

  A cracker might use this flaw to kill this service or worse, execute arbitrary code on your server.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("smtp_func.inc");

port = get_kb_item("Services/smtp");
if (! port) port = 25;
if (get_kb_item('SMTP/'+port+'/broken')) exit(0);
if(! get_port_state(port)) exit(0);

host = get_host_name();

soc = open_sock_tcp(port);
if (! soc) exit(0);
banner = smtp_recv_banner(socket:soc);

cmds = make_list(
	"HELO",
	"EHLO",
	"MAIL FROM:",
	"RCPT TO:",
	"ETRN");
args = make_list(
	"test.example.org",
	"test.example.org",
	strcat("test@", host),
	strcat("test@[", get_host_ip(), "]"),
	"test.example.org");
n = max_index(cmds);

for (i = 0; i < n; i ++)
{
  ##display("cmd> ", cmds[i], "\n");
  send(socket: soc,
       data: string(cmds[i], " ",
                    str_replace(string: args[i],
                                find: "test",
                                replace: crap(4095)),
                    "\r\n"));
  repeat
  {
    data = recv_line(socket: soc, length: 32768);
    ##display("data>  ", data);
  }
  until (data !~ '^[0-9][0-9][0-9]-');
  # A Postfix bug: it answers with two codes on an overflow
  repeat
  {
    data2 = recv_line(socket: soc, length: 32768, timeout: 1);
    ##if (data2) display("data2> ", data2);
  }
  until (data2 !~ '^[0-9][0-9][0-9]-');

  if (! data)
  {
    close(soc);
    soc = open_sock_tcp(port);
    if (! soc)
    {
      security_message(port);
      exit(0);
    }
    for (j = 0; j <= i; j ++)
    {
      send(socket: soc, data: string(cmds[i], " ", args[i], "r\n"));
      data = recv_line(socket: soc, length: 32768);
    }
  }
}

send(socket: soc, data: 'QUIT\r\n');
data = recv_line(socket: soc, length: 32768);
close(soc);
