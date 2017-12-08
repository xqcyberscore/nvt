# OpenVAS Vulnerability Test
# $Id: cherokee_0_4_7.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Cross-Site Scripting in Cherokee Error Pages
#
# Authors:
# David Maciejak
#
# Copyright:
# Copyright (C) 2004 David Maciejak
# Copyright (C) Tenable Network Security
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

The remote host is running Cherokee - a fast and tiny web server.

Due to a lack of sanitization from the user input, 
The remote version of this software is vulnerable to cross-site
scripting attacks due to lack of sanitization in returned error pages.";

tag_solution = "Upgrade to Cherokee 0.4.8 or newer.";

if(description)
{
 script_id(15618);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2004-2171");
 script_bugtraq_id(9496);
 script_xref(name:"OSVDB", value:3707);

 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 name = "Cross-Site Scripting in Cherokee Error Pages";

 script_name(name);
 
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2004 David Maciejak");
 family = "Web Servers";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Cherokee/banner");
 script_require_ports("Services/www", 443);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Cherokee/0\.([0-3]\.|4\.[0-7])[^0-9]", string:serv))
 {
   req = http_get(item:"/<script>foo</script>", port:port);
   res = http_keepalive_send_recv(port:port, data:req);
   if (res !~ "HTTP/1\.. 200" || "<script>foo</script>" >!< res ) exit(0);

   security_message(port);
 }
