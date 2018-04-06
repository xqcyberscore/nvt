# OpenVAS Vulnerability Test
# $Id: imp_html_mime_viewer_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: IMP HTML MIME Viewer XSS Vulnerabilities
#
# Authors:
# George A. Theall, <theall@tifaware.com>.
#
# Copyright:
# Copyright (C) 2003-2004 George A. Theall
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

tag_summary = "The target is running at least one instance of IMP whose version number
is between 3.0 and 3.2.5 inclusive.  Such versions are vulnerable to
several XSS attacks when viewing HTML messages with the HTML MIME viewer
and certain browsers.  For additional information, see the 3.2.6 release
announcement:

  http://lists.horde.org/archives/imp/Week-of-Mon-20040920/039246.html

***** OpenVAS has determined the vulnerability exists on the target
***** simply by looking at the version number of IMP installed there.";

tag_solution = "Upgrade to IMP version 3.2.6 or later.";

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.15393");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 
  name = "IMP HTML MIME Viewer XSS Vulnerabilities";
  script_name(name);
 
  summary = "Checks for HTML MIME Viewer XSS vulnerabilities in IMP";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2003-2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "imp_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for HTML MIME Viewer XSS vulnerability in IMP on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/imp"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ereg(pattern:"^3\.(0|1|2|2\.[1-5])$", string:ver)) {
      security_message(port);
      exit(0);
    }
  }
}
