# OpenVAS Vulnerability Test
# $Id: imap_unencrypted_cleartext_logins.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IMAP Unencrypted Cleartext Logins
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

tag_summary = "The remote host is running an IMAP daemon that allows cleartext logins over
unencrypted connections.  An attacker can uncover user names and
passwords by sniffing traffic to the IMAP daemon if a less secure
authentication mechanism (eg, LOGIN command, AUTH=PLAIN, AUTH=LOGIN)
is used.";

tag_solution = "Contact your vendor for a fix or encrypt traffic with SSL /
TLS using stunnel.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.15856");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");

  script_xref(name:"OSVDB", value:"3119");

  name = "IMAP Unencrypted Cleartext Logins";
  script_name(name);
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  script_family("General");

  script_dependencies("find_service.nasl", "global_settings.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/login", "imap/password");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.ietf.org/rfc/rfc2222.txt");
  script_xref(name : "URL" , value : "http://www.ietf.org/rfc/rfc2595.txt");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

# nb: non US ASCII characters in user and password must be 
#     represented in UTF-8.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) display("imap/login and/or imap/password are empty; ", SCRIPT_NAME, " skipped!\n");
  exit(1);
}

port = get_kb_item("Services/imap");
if (!port) port = 143;
debug_print("checking if IMAP daemon on port ", port, " allows unencrypted cleartext logins.");
if (!get_port_state(port)) exit(0);
# nb: skip it if traffic is encrypted.
encaps = get_port_transport( port );
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

# Determine server's capabilities.
#
# - look for it in the server's banner.
pat = "CAPABILITY ([^]]+)";
matches = egrep(string:s, pattern:pat, icase:TRUE);
foreach match (split(matches)) {
  match = chomp(match);
  debug_print("grepping >>", match, "<< for =>>", pat, "<<");
  caps = eregmatch(pattern:pat, string:match, icase:TRUE);
  if (!isnull(caps)) caps = caps[1];
}
# - try the CAPABILITY command.
if (isnull(caps)) {
  ++tag;
  c = string("a", string(tag), " CAPABILITY");
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    pat = "^* CAPABILITY (.+)";
    debug_print("grepping '", s, "' for '", pat, "'.");
    caps = eregmatch(pattern:pat, string:s, icase:TRUE);
    if (!isnull(caps)) caps = caps[1];
  }
}

# Try to determine if problem exists from server's capabilities; 
# otherwise, try to actually log in.
done = 0;
if (!isnull(caps)) {
  if (caps =~ "AUTH=(PLAIN|LOGIN)") {
    security_message(port);
    done = 1;
  }
  else if (caps =~ "LOGINDISABLED") {
    # there's no problem.
    done = 1;
  }
}
if (!done) {
  # nb: there's no way to distinguish between a bad username / password
  #     combination and disabled unencrypted logins. This makes it 
  #     important to configure the scan with valid IMAP username /
  #     password info.

  # - try the PLAIN SASL mechanism.
  ++tag;
  c = string("a", string(tag), ' AUTHENTICATE "PLAIN"');
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");
  if (s =~ "^\+") {
    c = base64(str:raw_string(0, user, 0, pass));
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
  }
  # nb: the obsolete LOGIN SASL mechanism is also dangerous. Since the
  #     PLAIN mechanism is required to be supported, though, I won't
  #     bother to check for the LOGIN mechanism.

  # If that didn't work, try LOGIN command.
  if (isnull(resp)) {
    ++tag;
    c = string("a", string(tag), " LOGIN ", user, " ", pass);
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
  }

  # If successful, unencrypted logins are possible.
  if (resp && resp =~ "OK") security_message(port);
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
