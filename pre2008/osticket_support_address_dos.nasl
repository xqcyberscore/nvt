# OpenVAS Vulnerability Test
# $Id: osticket_support_address_dos.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: osTicket Support Address DoS
#
# Authors:
# George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) George A. Theall
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

tag_summary = "The target is running at least one instance of osTicket 1.2.7 or
earlier.  Such versions are subject to a denial of service attack in
open.php if osTicket is configured to receive mails using aliases.  If
so, a remote attacker can generate a mail loop on the target by opening
a ticket with the support address as the contact email address. For 
details, see :

  - http://www.osticket.com/forums/showthread.php?t=301

***** OpenVAS has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of osTicket installed 
***** there. It has no way of knowing which method osTicket uses to
***** retrieve mail.";

tag_solution = "Configure osTicket to receive mail using POP3.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.13859");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"0.0");
   name = "osTicket Support Address DoS";
  script_name(name);
 
  summary = "Checks for Support Address DoS osTicket";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Denial of Service";
  script_family(family);

  script_dependencies("global_settings.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for Support Address DoS vulnerability in osTicket on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ereg(pattern:"^1\.(0|1|2|2\.[0-7])$", string:ver)) {
      log_message(port);
      exit(0);
    }
  }
}
