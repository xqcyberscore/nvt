# OpenVAS Vulnerability Test
# $Id: imp_status_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Horde IMP status.php3 XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from George A. Theall, <theall@tifaware.com>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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

tag_summary = "The remote host is running at least one instance of Horde IMP in which the
status.php3 script is vulnerable to a cross site scripting attack since
information passed to it is not properly sanitized.";

tag_solution = "Upgrade to IMP version 2.2.8 or later.";

#  Ref: Nuno Loureiro <nuno@eth.pt>

if (description) {
  script_oid("1.3.6.1.4.1.25623.1.0.15616");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(4444);
  script_cve_id("CVE-2002-0181");
  
  script_xref(name:"OSVDB", value:"5345");

  name = "Horde IMP status.php3 XSS";
  script_name(name);

  summary = "Checks for status.php3 XSS flaw in Horde IMP";
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");


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
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

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

    url = string(
      dir, 
      # nb: if you change the URL, you probably need to change the 
      #     pattern in the egrep() below.
      "/status.php3?script=<script>foo</script>"
    );
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (isnull(res)) exit(0);
           
    if (res =~ "HTTP/1\.. 200" && egrep(string:res, pattern:'<script>foo</script>')) {
      security_message(port);
      exit(0);
    }
  }
}
