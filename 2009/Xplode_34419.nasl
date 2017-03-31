###############################################################################
# OpenVAS Vulnerability Test
# $Id: Xplode_34419.nasl 5231 2017-02-08 11:52:34Z teissa $
#
# Xplode 'module_wrapper.asp' SQL Injection and Cross Site Scripting
# Vulnerabilities
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Xplode is prone to an SQL-injection vulnerability and a cross-site
  scripting vulnerability because it fails to sufficiently sanitize
  user-supplied data.

  Exploiting these issues could allow an attacker to steal
  cookie-based authentication credentials, compromise the application,
  access or modify data, or exploit latent vulnerabilities in the
  underlying database.";


if (description)
{
 script_id(100113);
 script_version("$Revision: 5231 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-08 12:52:34 +0100 (Wed, 08 Feb 2017) $");
 script_tag(name:"creation_date", value:"2009-04-08 20:52:50 +0200 (Wed, 08 Apr 2009)");
 script_bugtraq_id(34419);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("Xplode 'module_wrapper.asp' SQL Injection and Cross Site Scripting Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/34419");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_asp(port:port)) exit(0);

dir = make_list("/cms", cgi_dirs());

foreach d (dir)
{ 
 url = string(d, '/module_wrapper.asp?wrap_script=modules/Search+results/search.asp&SearchType=all&SearchString=">><script>alert(document.cookie)</script>');
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 
 if( buf == NULL )continue;

 if (egrep(pattern:"<script>alert\(document\.cookie\)</script>", string: buf && "HTTP/1.1 200" >< buf) )
 	{    
       	  security_message(port:port);
          exit(0);
        }
}

exit(0);
