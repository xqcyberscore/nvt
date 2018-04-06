# OpenVAS Vulnerability Test
# $Id: osticket_view_attachments.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: osTicket Attachment Viewing Vulnerability
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

tag_summary = "The target is running at least one instance of osTicket that enables a
remote user to view attachments associated with any existing ticket. 
These attachments may contain sensitive information.";

tag_solution = "Upgrade to osTicket STS 1.2.7 or later.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.13648");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2004-0613");
  script_bugtraq_id(10586);

  name = "osTicket Attachment Viewing Vulnerability";
  script_name(name);
 
  summary = "Checks for Attachment Viewing Vulnerability in osTicket";
 
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "http_version.nasl", "no404.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for attachment viewing vulnerability in osTicket on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);
if (get_kb_item("www/no404/" + port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # Try to browse osTicket's attachments directory.
    url = string(dir, "/attachments/");
    if (debug_level) display("debug: checking ", url, ".\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (res == NULL) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    # If successful, there's a problem.
    if (ereg(pattern:"200 OK", string:res, icase:TRUE) && "[DIR]" >< res ) {
      security_message(port:port);
      exit(0);
    }
  }
}
