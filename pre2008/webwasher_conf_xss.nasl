# OpenVAS Vulnerability Test
# $Id: webwasher_conf_xss.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: WebWasher < 4.4.1 Build 1613 Multiple Vulnerabilities
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
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

tag_summary = "The remote web proxy suffers from multiple flaws.

Description : 

The remote host is running the web proxy WebWasher.

According to its banner, the installed version of WebWasher is prone to
multiple cross-site scripting flaws.  Successful exploitation of these
issues may allow an attacker to execute malicious script code in a
user's browser within the context of the affected website.";

tag_solution = "Upgrade to WebWasher CSM 4.4.1 Build 1613 or later.";

#  Ref: Oliver Karow

if(description)
{
 script_id(19946);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_bugtraq_id(9039, 13037); 
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 name = "WebWasher < 4.4.1 Build 1613 Multiple Vulnerabilities";

 script_name(name);
 
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2005 David Maciejak");
 script_family("Web application abuses");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 8080, 9090);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.oliverkarow.de/research/WebWasherXSS.txt");
 script_xref(name : "URL" , value : "http://www.oliverkarow.de/research/wwcsm.txt");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:9090);

if(!get_port_state(port))exit(0);

req = http_get(item:"/openvas345678.html", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
if( r == NULL )exit(0);

if ( ("<title>WebWasher - " >< r))
{
 if (egrep(pattern:"generated .* by .* \(WebWasher ([0-3]\..*|4\.([0-3] .*|4\.1 .uild ([0-9][0-9][0-9]|1([0-5][0-9][0-9]|6(0[0-9]|1[0-2])))))\)", string:r))
 {
   security_message(port);
   exit(0);
 }
}
