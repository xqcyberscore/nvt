# OpenVAS Vulnerability Test
# $Id: basilix_content_type_xss.nasl 3376 2016-05-24 07:53:16Z antu123 $
# Description: BasiliX Content-Type XSS Vulnerability
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

tag_summary = "The remote web server contains a PHP script which is vulnerable to a 
cross site scripting issue.

Description :

The remote host appears to be running BasiliX version 1.1.1 or lower. 
Such versions are vulnerable to a cross-scripting attack whereby an
attacker may be able to cause a victim to unknowingly run arbitrary
Javascript code simply by reading a MIME message with a specially
crafted Content-Type header.";

tag_solution = "Upgrade to BasiliX version 1.1.1 fix1 or later.";

if (description) {
  script_id(14307);
  script_version("$Revision: 3376 $");
  script_tag(name:"last_modification", value:"$Date: 2016-05-24 09:53:16 +0200 (Tue, 24 May 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_bugtraq_id(10666);

  name = "BasiliX Content-Type XSS Vulnerability";
  script_name(name);
 


 
  summary = "Checks for Content-Type XSS vulnerability in BasiliX";
  script_summary(summary);
 
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");

  script_copyright("This script is Copyright (C) 2004 George A. Theall");

  script_dependencies("basilix_detect.nasl");
  script_require_ports("Services/www", 80);

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt");
  script_xref(name : "URL" , value : "http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/basilix"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (ver =~ "^(0\..*|1\.0.*|1\.1\.(0|1))$") {
    security_message(port);
    exit(0);
  }
}
