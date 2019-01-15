###############################################################################
# OpenVAS Vulnerability Test
# $Id: smtp_relay.nasl 13077 2019-01-15 10:37:47Z cfischer $
#
# SMTP Open Relay Test
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100073");
  script_version("$Revision: 13077 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-15 11:37:47 +0100 (Tue, 15 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-03-23 19:32:33 +0100 (Mon, 23 Mar 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Mail relaying");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("SMTP problems");
  script_dependencies("smtpserver_detect.nasl", "smtp_settings.nasl", "global_settings.nasl");
  script_exclude_keys("keys/is_private_addr", "keys/islocalhost", "SMTP/wrapped", "SMTP/qmail");
  script_require_ports("Services/smtp", 25, 465, 587);

  script_tag(name:"solution", value:"Improve the configuration of your SMTP server so that your SMTP server
  cannot be used as a relay any more.");

  script_tag(name:"summary", value:"The remote SMTP server is insufficiently protected against mail relaying.");

  script_tag(name:"impact", value:"This means that spammers might be able to use your mail server
  to send their mails to the world.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("network_func.inc");

if(islocalhost()) exit(0);
if(is_private_addr()) exit(0);

domain = get_3rdparty_domain();
src_name = this_host_name();
vtstrings = get_vt_strings();
FROM = string(vtstrings["lowercase"], '@', src_name);
TO = string(vtstrings["lowercase"], '@', domain);

port = get_smtp_port(default:25);
soc = smtp_open(port: port, helo: NULL);
if(!soc) exit(0);

send(socket: soc, data: strcat('EHLO ', src_name, '\r\n'));
answer = smtp_recv_line(socket: soc);

if("250" >!< answer) exit(0);

mf = strcat('MAIL FROM: <', FROM , '>\r\n');
send(socket: soc, data: mf);
l = smtp_recv_line(socket: soc);

if(! l || l =~ '^5[0-9][0-9]')
{
  exit(0);
}
else
{
  rt = strcat('RCPT TO: <', TO , '>\r\n');
  send(socket: soc, data: rt);
  l = smtp_recv_line(socket: soc);

  if (l =~ '^2[0-9][0-9]')
  {
    data=string("data\r\n");
    send(socket: soc, data: data);
    data_rcv = smtp_recv_line(socket: soc);

    if(egrep(pattern:"3[0-9][0-9]", string:data_rcv)) {

      send(socket: soc, data: string(vtstrings["default"], "-Relay-Test\r\n.\r\n"));
      mail_send = smtp_recv_line(socket: soc);

      if("250" >< mail_send) {
        security_message(port:port);
        set_kb_item(name:"SMTP/" + port + "/spam", value:TRUE);
        set_kb_item(name:"SMTP/spam", value:TRUE);
        smtp_close(socket: soc);
        exit(0);
      }
    }
  }
  smtp_close(socket: soc);
}

exit(99);