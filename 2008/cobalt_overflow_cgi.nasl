# OpenVAS Vulnerability Test
# $Id: cobalt_overflow_cgi.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: overflow.cgi detection
#
# Authors:
# Renaud Deraison <deraison@cvs.nessus.org>
#
# Copyright:
# Copyright (C) 2002 Renaud Deraison
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

tag_summary = "/cgi-bin/.cobalt/overflow/overflow.cgi was detected.
Some versions of this CGI allow remote users to execute arbitrary commands
with the privileges of the web server.

*** OpenVAS just checked the presence of this file 
*** but did not try to exploit the flaw, so this might
*** be a false positive
   
See: http://www.cert.org/advisories/CA-2002-35.html";

tag_solution = "get a newer software from Cobalt";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.80051");;
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 name = "overflow.cgi detection";
 script_name(name);
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2002 Renaud Deraison");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 81, 444);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

res = is_cgi_installed_ka(item:"/cgi-bin/.cobalt/overflow/overflow.cgi", port:port);
if(res) security_message(port);
