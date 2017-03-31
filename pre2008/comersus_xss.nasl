# OpenVAS Vulnerability Test
# $Id: comersus_xss.nasl 3520 2016-06-15 04:22:26Z ckuerste $
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
 script_id(12640);
 script_version("$Revision: 3520 $");
 script_tag(name:"last_modification", value:"$Date: 2016-06-15 06:22:26 +0200 (Wed, 15 Jun 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-0681", "CVE-2004-0682");
 script_bugtraq_id(10674);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "Comersus Cart Cross-Site Scripting Vulnerability";

 script_name(name);
 

 summary = "Checks for the presence of an XSS bug in Comersus";
 
 script_summary(summary);
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("cross_site_scripting.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port))exit(0);
if (  get_kb_item(string("www/", port, "/generic_xss")) ) exit(0);

function check(loc)
{
 req = http_get(item:string(loc, "/comersus_message.asp?message=openvas<script>foo</script>"), port:port);

 r = http_keepalive_send_recv(port:port, data:req);
 if( r == NULL )exit(0);
 if(r =~ "HTTP/1\.. 200" && '<font size="2">openvas<script>foo</script>' >< r ) 
 {
 	security_message(port);
	exit(0);
 }
}

check(loc:"/comersus/store");
foreach dir (cgi_dirs())
{
 check(loc:dir);
}
