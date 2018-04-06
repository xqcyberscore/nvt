# OpenVAS Vulnerability Test
# $Id: xedus_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Xedus XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

tag_summary = "The remote host runs Xedus Peer to Peer webserver.
This version is vulnerable to cross-site scripting attacks.

With a specially crafted URL, an attacker can cause arbitrary
code execution resulting in a loss of integrity.";

tag_solution = "Upgrade to the latest version and
remove .x files located in ./sampledocs folder";

# Ref: James Bercegay of the GulfTech Security Research Team

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.14647");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1645");
  script_bugtraq_id(11071);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Xedus XSS");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_dependencies("xedus_detect.nasl", "cross_site_scripting.nasl");
  script_family("Peer-To-Peer File Sharing");
  script_require_ports("Services/www", 4274);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:4274);
if ( ! get_kb_item("xedus/" + port + "/running")) exit(0);

if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(get_port_state(port))
{
 soc = http_open_socket(port);
 if(soc)
 {
  buf = http_get(item:"/test.x?username=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf);
  if( r == NULL )exit(0);
  if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_message(port);
	exit(0);
  }
  buf = http_get(item:"/TestServer.x?username=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf);
  if( r == NULL )exit(0);
  if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_message(port);
	exit(0);
  }
  buf = http_get(item:"/testgetrequest.x?param=<script>foo</script>", port:port);
  r = http_keepalive_send_recv(port:port, data:buf);
  if( r == NULL )exit(0);
  if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
  {
 	http_close_socket(soc);
 	security_message(port);
	exit(0);
  }
  http_close_socket(soc);
 }
}
exit(0);
