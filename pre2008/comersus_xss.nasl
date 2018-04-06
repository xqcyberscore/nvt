# OpenVAS Vulnerability Test
# $Id: comersus_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Comersus Cart Cross-Site Scripting Vulnerability
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

tag_summary = "The malicious user is able to compromise the parameters to invoke a
Cross-Site Scripting attack. This can be used to take advantage of the trust
between a client and server allowing the malicious user to execute malicious
JavaScript on the client's machine or perform a denial of service shutting
down IIS.";

tag_solution = "Upgrade to version 5.098 or newer";

# From: "Thomas Ryan" <tommy@providesecurity.com>
# Date: 7.7.2004 18:10
# Subject: Comersus Cart Cross-Site Scripting Vulnerability

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.12640");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-0681", "CVE-2004-0682");
 script_bugtraq_id(10674);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Comersus Cart Cross-Site Scripting Vulnerability");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port))exit(0);
if( get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

foreach dir( make_list_unique( "/comersus/store", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  req = http_get(item:string(dir, "/comersus_message.asp?message=openvas<script>foo</script>"), port:port);
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL )continue;

  if(r =~ "HTTP/1\.. 200" && '<font size="2">openvas<script>foo</script>' >< r ) {
    security_message(port);
    exit(0);
  }
}
