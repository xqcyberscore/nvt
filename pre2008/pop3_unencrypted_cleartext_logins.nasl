###############################################################################
# OpenVAS Vulnerability Test
# $Id: pop3_unencrypted_cleartext_logins.nasl 12150 2018-10-29 11:46:42Z cfischer $
#
# POP3 Unencrypted Cleartext Logins
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15855");
  script_version("$Revision: 12150 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 12:46:42 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_xref(name:"OSVDB", value:"3119");
  script_name("POP3 Unencrypted Cleartext Logins");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 George A. Theall");
  script_family("General");
  script_dependencies("find_service2.nasl", "global_settings.nasl", "logins.nasl");
  script_require_ports("Services/pop3", 110);
  script_mandatory_keys("pop3/login", "pop3/password");

  script_xref(name:"URL", value:"http://www.ietf.org/rfc/rfc2222.txt");
  script_xref(name:"URL", value:"http://www.ietf.org/rfc/rfc2595.txt");

  script_tag(name:"impact", value:"An attacker can uncover user names and passwords by sniffing traffic to the POP3
  daemon if a less secure authentication mechanism (eg, USER command, AUTH PLAIN, AUTH LOGIN) is used.");

  script_tag(name:"solution", value:"Contact your vendor for a fix or encrypt traffic with SSL /
  TLS using stunnel.");

  script_tag(name:"summary", value:"The remote host is running a POP3 daemon that allows cleartext logins over
  unencrypted connections.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_analysis");

  exit(0);
}

include("misc_func.inc");
include("pop3_func.inc");

# nb: non US ASCII characters in user and password must be
#     represented in UTF-8.
user = get_kb_item("pop3/login");
pass = get_kb_item("pop3/password");
if (!user || !pass) {
  exit(0);
}

port = get_pop3_port( default:110 );

# nb: skip it if traffic is encrypted.
encaps = get_port_transport( port );
if (encaps > ENCAPS_IP) exit(0);

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

c = "CAPA";
send(socket:soc, data:string(c, "\r\n"));
caps = "";
s = recv_line(socket:soc, length:1024);
s = chomp(s);
if (s =~ "^\+OK ") {
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    if (s =~ "^\.$") break;
    caps = string(caps, s, "\n");
  }
}

# otherwise, try to actually log in.
done = 0;
if (egrep(string:caps, pattern:"(SASL (PLAIN|LOGIN)|USER)", icase:TRUE)) {
  security_message(port);
  done = 1;
}
if (!done) {
  # nb: there's no way to distinguish between a bad username / password
  #     combination and disabled unencrypted logins. This makes it
  #     important to configure the scan with valid POP3 username /
  #     password info.

  # - try the PLAIN SASL mechanism.
  c = "AUTH PLAIN";
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);

  if (s =~ "^\+") {
    c = base64(str:raw_string(0, user, 0, pass));
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
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

  # If that didn't work, try USER command.
  if (isnull(resp)) {
    c = string("USER ", user);
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }

    if (resp && resp =~ "OK") {
      c = string("PASS ", pass);
      send(socket:soc, data:string(c, "\r\n"));
      while (s = recv_line(socket:soc, length:1024)) {
        s = chomp(s);
        m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
        if (!isnull(m)) {
          resp = m[1];
          break;
        }
        resp = "";
      }
    }
  }

  # If successful, unencrypted logins are possible.
  if (resp && resp =~ "OK") security_message(port);
}

# Logout.
c = "QUIT";

send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:"^(\+OK|-ERR) ", string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
