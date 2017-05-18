# OpenVAS Vulnerability Test
# $Id: merak_multiple_vulns.nasl 6053 2017-05-01 09:02:51Z teissa $
# Description: Multiple Vulnerabilities in Merak Webmail / IceWarp Web Mail
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

tag_summary = "The target is running at least one instance of Merak Webmail / IceWarp
Web Mail 5.2.7 or less or Merak Mail Server 7.5.2 or less -
<http://www.MerakMailServer.com/>.  This product is subject to
multiple XSS, HTML and SQL injection, and PHP source code disclosure
vulnerabilities.";

tag_solution = "Upgrade to Merak Webmail / IceWarp Web Mail 5.2.8 or
Merak Mail Server 7.5.2 or later.";

if (description) {
  script_id(14379);
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2004-1719", "CVE-2004-1720", "CVE-2004-1721", "CVE-2004-1722");
  script_bugtraq_id(10966);
  script_xref(name:"OSVDB", value:"9037");
  script_xref(name:"OSVDB", value:"9038");
  script_xref(name:"OSVDB", value:"9039");
  script_xref(name:"OSVDB", value:"9040");
  script_xref(name:"OSVDB", value:"9041");
  script_xref(name:"OSVDB", value:"9042");
  script_xref(name:"OSVDB", value:"9043");
  script_xref(name:"OSVDB", value:"9044");
  script_xref(name:"OSVDB", value:"9045");

  name = "Multiple Vulnerabilities in Merak Webmail / IceWarp Web Mail";
  script_name(name);
 
 
  summary = "Checks for Multiple Vulnerabilities in Merak Webmail / IceWarp Web Mail";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  family = "Web application abuses";
  script_family(family);

  script_dependencies("global_settings.nasl", "http_version.nasl");
  script_require_ports("Services/www", 4096);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
# nb: if webmail component installed, it's defaults to 4096;
#     if mail server, it's on 32000.
port = get_http_port(default:4096);
if (debug_level) display("debug: searching for multiple vulnerabilities in Merak WebMail / IceWarp Web Mail on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# nb: software is accessible through either "/mail" (default) or "/".
dirs = make_list("/mail", "");
foreach dir (dirs) {

  # Try to retrieve inc/function.php since it's accessible in vulnerable versions.
  url = string(dir, "/inc/function.php");
  if (debug_level) display("debug: checking ", url, "...\n");

  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0);           # can't connect
  if (debug_level) display("debug: res =>>", res, "<<\n");

  # Check the server signature as well as the content of the file retrieved.
  if (
    egrep(string:res, pattern:"^Server: IceWarp", icase:TRUE) &&
    egrep(string:res, pattern:"function getusersession", icase:TRUE)
  ) {
    security_message(port:port);
    exit(0);
  }
}
