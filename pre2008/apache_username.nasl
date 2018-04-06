# OpenVAS Vulnerability Test
# $Id: apache_username.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Apache UserDir Sensitive Information Disclosure
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
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

tag_summary = "An information leak occurs on Apache based web servers 
whenever the UserDir module is enabled. The vulnerability allows an external 
attacker to enumerate existing accounts by requesting access to their home 
directory and monitoring the response.";

tag_solution = "1) Disable this feature by changing 'UserDir public_html' (or whatever) to 
'UserDir  disabled'.

Or

2) Use a RedirectMatch rewrite rule under Apache -- this works even if there 
is no such  entry in the password file, e.g.:
RedirectMatch ^/~(.*)$ http://my-target-webserver.somewhere.org/$1

Or

3) Add into httpd.conf:
ErrorDocument 404 http://localhost/sample.html
ErrorDocument 403 http://localhost/sample.html
(NOTE: You need to use a FQDN inside the URL for it to work properly).

Additional Information:
http://www.securiteam.com/unixfocus/5WP0C1F5FI.html";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10766"); 
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(3335);
 script_cve_id("CVE-2001-1013");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 name = "Apache UserDir Sensitive Information Disclosure";
 script_name(name);



 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");

 script_copyright("This script is Copyright (C) 2001 SecuriTeam");
 family = "Web Servers";
 script_family(family);

 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);


if (! get_port_state(port)) exit(0);

soc = http_open_socket(port);
if(! soc) exit(0);


soc = http_open_socket(port);
if (soc)
{
 req = http_head(item:"/~root", port:port);
 send(socket:soc, data:req);
 buf_valid = recv_line(socket:soc, length:1000);
 http_close_socket(soc);
}

soc = http_open_socket(port);
if (soc)
{
 req = http_head(item:"/~anna_foo_fighter", port:port);
 send(socket:soc, data:req);
 buf_invalid = recv_line(socket:soc, length:1000);
 http_close_socket(soc);
}

if (("403 Forbidden" >< buf_valid) && ("404 Not Found" >< buf_invalid))
{
 security_message(port);
}
