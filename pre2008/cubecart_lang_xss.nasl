# OpenVAS Vulnerability Test
# $Id: cubecart_lang_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Brooky CubeCart index.php language XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# Updated: 04/07/2009 Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote host runs CubeCart, is an eCommerce script written with PHP & MySQL.
  This version is vulnerable to cross-site scripting and remote script
  injection due to a lack of sanitization of user-supplied data.
  Successful exploitation of this issue may allow an attacker to execute
  malicious script code on a vulnerable server.";

tag_solution = "Upgrade to version 2.0.5 or higher";

# Ref: John Cobb

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.17227");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(12549);
  script_cve_id("CVE-2005-0442", "CVE-2005-0443");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Brooky CubeCart index.php language XSS");
  script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("secpod_cubecart_detect.nasl");
  script_mandatory_keys("cubecart/installed");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

port = get_http_port(default:80);
version = get_kb_item(string("www/", port, "/cubecart"));
if(!version) exit(0);

if(!safe_checks())
{
  foreach dir( make_list_unique( "/cubecart/upload", "/upload", cgi_dirs( port:port ) ) ) {
    if( dir == "/" ) dir = "";
    url = string(dir,"/index.php?&language=<script>foo</script>");
    buf = http_get(item:url, port:port);
    r = http_keepalive_send_recv(port:port, data:buf);
    if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r)){
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

if(version_is_less_equal(version:version, test_version:"2.0.4")){
  security_message( port:port );
  exit( 0 );
}

exit( 99 );