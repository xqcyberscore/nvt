# OpenVAS Vulnerability Test
# $Id: keene_xss.nasl 6053 2017-05-01 09:02:51Z teissa $
# Description: Keene digital media server XSS
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

tag_summary = "The remote host runs Keene digital media server, a webserver
used to share digital information.


This version is vulnerable to multiple cross-site scripting attacks which
may allow an attacker to steal the cookies of users of this site.";

tag_solution = "Upgrade to the latest version of this software";

# Ref: Dr_insane

if(description)
{
  script_id(14681);
  script_version("$Revision: 6053 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-01 11:02:51 +0200 (Mon, 01 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(11111);
  script_xref(name:"OSVDB", value:9514);
  script_xref(name:"OSVDB", value:9515);
  script_xref(name:"OSVDB", value:9516);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Keene digital media server XSS");

 

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

buf = http_get(item:"/dms/slideshow.kspx?source=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
 if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_message(port);
	exit(0);
  }
buf = http_get(item:"/dms/dlasx.kspx?shidx=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
  if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_message(port);
	exit(0);
  }
buf = http_get(item:"/igen/?pg=dlasx.kspx&shidx=<script>foo</script>", port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_message(port);
	exit(0);
  }
buf = http_get(item:"/dms/mediashowplay.kspx?pic=<script>foo</script>&idx=0", port:port);
 r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
 if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_message(port);
	exit(0);
  }
buf = http_get(item:"/dms/mediashowplay.kspx?pic=0&idx=<script>foo</script>", port:port);
r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
if( r == NULL )exit(0);
if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_message(port);
	exit(0);
  }
