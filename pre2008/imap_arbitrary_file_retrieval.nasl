# OpenVAS Vulnerability Test
# $Id: imap_arbitrary_file_retrieval.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IMAP arbitrary file retrieval
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

tag_summary = "The target is running an IMAP daemon that allows an authenticated user
to retrieve and manipulate files that would be available to that user
via a shell.  If IMAP users are denied shell access, you may consider
this a vulnerability.";

tag_solution = "Contact your vendor for a fix.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.12254");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2002-1782");
  script_bugtraq_id(4909);

  name = "IMAP arbitrary file retrieval";
  script_name(name);

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Remote file access";
  script_family(family);

  script_dependencies("find_service.nasl", "global_settings.nasl", "logins.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/login", "imap/password");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.washington.edu/imap/IMAP-FAQs/index.html#5.1");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

file = "/etc/group";                    # file to grab from target.
user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if (!user || !pass) {
  if (log_verbosity > 1) display("imap/login and/or imap/password are empty; ", SCRIPT_NAME, " skipped!\n");
  exit(1);
}

port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);

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

# Try to log in.
#
# - try the PLAIN SASL mechanism.
#   nb: RFC 3501 requires this be supported by imap4rev1 servers, although
#       it may also require SSL / TLS encapsulation.
++tag;
c = string("a", string(tag), ' AUTHENTICATE "PLAIN"');
send(socket:soc, data:string(c, "\r\n"));
s = recv_line(socket:soc, length:1024);
s = chomp(s);
if (s =~ "^\+") {
  c = base64(str:raw_string(0, user, 0, pass));
  send(socket:soc, data:string(c, "\r\n"));
  # nb: I'm not sure why, but the following recv_line often times out
  #     unless I either sleep for a bit before or specify a timeout
  #     even though the actual delay / timeout seems irrelevant.
  while (s = recv_line(socket:soc, length:1024, timeout:1)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }
}

# If that didn't work, try LOGIN command.
if (isnull(resp)) {
  ++tag;
  c = string("a", string(tag), " LOGIN ", user, " ", pass);
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }
}

# If successful, try to select an arbitrary file to use as a mailbox.
if (resp && resp =~ "OK") {
  ++tag;
  c = string("a", string(tag), ' SELECT "', file, '"');
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
    resp = "";
  }

  # If successful, try to read the file.
  #
  # NB: this isn't really necessary since the previous command,
  #     if successful, means we can read the file.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string("a", string(tag), " FETCH 1 rfc822");
    send(socket:soc, data:string(c, "\r\n"));
    while (s = recv_line(socket:soc, length:1024)) {
      s = chomp(s);
      m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
      if (!isnull(m)) {
        resp = m[1];
        break;
      }
      resp = "";
    }
    if (resp && resp =~ "OK") security_message(port);
  }
}

# Logout.
++tag;
c = string("a", string(tag), " LOGOUT");
send(socket:soc, data:string(c, "\r\n"));
while (s = recv_line(socket:soc, length:1024)) {
  s = chomp(s);
  m = eregmatch(pattern:string("^a", string(tag), " (OK|BAD|NO)"), string:s, icase:TRUE);
  if (!isnull(m)) {
    resp = m[1];
    break;
  }
  resp = "";
}
close(soc);
