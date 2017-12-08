# OpenVAS Vulnerability Test
# $Id: fcgi_echo.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: FastCGI samples Cross Site Scripting
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
#
# Copyright:
# Copyright (C) 2002 Matt Moore
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

tag_solution = "Always remove sample applications from production servers.";
tag_summary = "Two sample CGI's supplied with FastCGI are vulnerable 
to cross-site scripting attacks. FastCGI is an 'open extension to CGI 
that provides high performance without the limitations of server 
specific APIs', and is included in the default installation of the 
'Unbreakable' Oracle9i Application Server. Various other web servers 
support the FastCGI extensions (Zeus, Pi3Web etc).

Two sample CGI's are installed with FastCGI, (echo.exe and echo2.exe
under Windows, echo and echo2 under Unix). Both of these CGI's output
a list of environment variables and PATH information for various
applications. They also display any parameters that were provided
to them. Hence, a cross site scripting attack can be performed via
a request such as: 

http://www.someserver.com/fcgi-bin/echo2.exe?blah=<SCRIPT>alert(document.domain)</SCRIPT>";


if(description)
{
 script_id(10838);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 name = "FastCGI samples Cross Site Scripting";
 script_name(name);
 
 
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_analysis");
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(! get_port_state(port)) exit(0);

# Avoid FP against Compaq Web Management or HTTP proxy
if (get_kb_item('www/'+port+'/generic_xss')) exit(0);

file = make_list("echo", "echo.exe", "echo2", "echo2.exe");
 
for(f = 0; file[f]; f++)
 {
  req = http_get(item:string("/fcgi-bin/", file[f], "?foo=<SCRIPT>alert(document.domain)</SCRIPT>"), port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if ( r == NULL ) exit(0);
  if(r =~ "HTTP/1\.. 200" && "<SCRIPT>alert(document.domain)</SCRIPT>" >< r) 
	{
  	security_message(port);
	exit(0);
	}
 }	

