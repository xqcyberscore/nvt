# OpenVAS Vulnerability Test
# $Id: cutenews_indexphp_xss.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: CuteNews index.php XSS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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

tag_summary = "The remote web server contains a PHP script that is prone to
cross-site scripting attacks. 

Description :

The version of CuteNews installed on the remote host is vulnerable to
a cross-site-scripting (XSS) attack.  An attacker, exploiting this
flaw, would need to be able to coerce a user to browse to a
purposefully malicious URI.  Upon successful exploitation, the
attacker would be able to run code within the web-browser in the
security context of the CuteNews server.";

tag_solution = "Upgrade to the latest version.";

# Ref: Exoduks <exoduks@gmail.com> 

if(description)
{
 script_id(14665);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-1659");
 script_bugtraq_id(11097);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 
 name = "CuteNews index.php XSS";

 script_name(name);
 
 
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 
 family = "Web application abuses";
  script_family(family);
 script_dependencies("cutenews_detect.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://marc.theaimsgroup.com/?l=bugtraq&m=109415338521881&w=2");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( get_kb_item("www/" + port + "/generic_xss") ) exit(0);

if(!get_port_state(port))
	exit(0);
if(!can_host_php(port:port)) 
	exit(0);



# Test an install.
install = get_kb_item(string("www/", port, "/cutenews"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  loc = matches[2];

  req = http_get(item:string(loc, "/index.php?mod=<script>foo</script>"),
 		port:port);			
  r = http_keepalive_send_recv(port:port, data:req);
  if( r == NULL ) exit(0);
  if(r =~ "HTTP/1\.. 200" && egrep(pattern:"<script>foo</script>", string:r))
  {
 	security_message(port);
	exit(0);
  }
}
