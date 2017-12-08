# OpenVAS Vulnerability Test
# $Id: Jserv_css.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: JServ Cross Site Scripting
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

tag_summary = "The remote web server is vulnerable to a cross-site scripting issue.

Description :

Older versions of JServ (including the version shipped with Oracle9i App 
Server v1.0.2) are vulnerable to a cross site scripting attack using a 
request for a non-existent .JSP file.";

tag_solution = "Upgrade to the latest version of JServ available at http://java.apache.org. 
Also consider switching from JServ to TomCat, since JServ is no longer 
maintained.";

if(description)
{
 script_id(10957);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 name = "JServ Cross Site Scripting";
 script_name(name);
 
 
 
 script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web Servers";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("apache/banner");

 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Check starts here
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_kb_item(string("www/", port, "/generic_xss")))exit(0);

banner = get_http_banner( port:port );
if( "Apache" >!< banner ) exit(0);

 req = http_get(item:"/a.jsp/<SCRIPT>alert(document.domain)</SCRIPT>", port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
 if( res == NULL ) exit(0);
 if(res =~ "HTTP/1\.. 200" && "<SCRIPT>alert(document.domain)</SCRIPT>" >< res) security_message(port);
