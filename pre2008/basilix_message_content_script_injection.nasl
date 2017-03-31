# OpenVAS Vulnerability Test
# $Id: basilix_message_content_script_injection.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: BasiliX Message Content Script Injection Vulnerability
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

tag_summary = "The remote web server contains PHP scripts that are prone to cross-site
scripting attacks. 

Description :

The remote host appears to be running a BasiliX version 1.1.0 or lower. 
Such versions are vulnerable to cross-scripting attacks since they do
not filter HTML tags when showing a message.  As a result, an attacker
can include arbitrary HTML and script code in a message and have that
code executed by the user's browser when it is viewed.";

tag_solution = "Upgrade to BasiliX version 1.1.1 or later.";

if (description) {
  script_id(14218);
  script_version("$Revision: 3362 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2002-1708");
  script_bugtraq_id(5060);

  name = "BasiliX Message Content Script Injection Vulnerability";
  script_name(name);
 
 
  summary = "Checks for message content script injection vulnerability in BasiliX";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");

  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  script_dependencies("basilix_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/vulnwatch/2002-q2/0117.html");
  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\..*|1\.(0.*|1\.0))$") {
    security_message(port);
    exit(0);
  }
}
