# OpenVAS Vulnerability Test
# $Id: ipswitch_whatsup_info_disclosure.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: Ipswitch WhatsUp Professional Multiple Vulnerabilities
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2006 David Maciejak
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

tag_summary = "The remote web server is affected by multiple flaws. 

Description :

The remote host appears to be running Ipswitch WhatsUp Professional,
which is used to monitor states of applications, services and hosts. 

The version of WhatsUp Professional installed on the remote host is
prone to multiple issues, including source code disclosure and
cross-site scripting vulnerabilities.";

tag_solution = "Unknown at this time.";

if(description)
{
 script_id(80068);;
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2008-10-24 23:33:44 +0200 (Fri, 24 Oct 2008)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

 script_cve_id("CVE-2006-2351", "CVE-2006-2352", "CVE-2006-2353", "CVE-2006-2354", "CVE-2006-2355", "CVE-2006-2356", "CVE-2006-2357");
 script_bugtraq_id(17964);
 script_xref(name:"OSVDB", value:"25469");
 script_xref(name:"OSVDB", value:"25470");
 script_xref(name:"OSVDB", value:"25471");
 script_xref(name:"OSVDB", value:"25472");

 name = "Ipswitch WhatsUp Professional Multiple Vulnerabilities";
 script_name(name);
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 
 script_copyright("This script is Copyright (C) 2006 David Maciejak");
 
 family = "Web application abuses";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 8022);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/433808/30/0/threaded");
 script_xref(name : "URL" , value : "http://www.ipswitch.com/products/whatsup/professional/");
 script_mandatory_keys("Ipswitch/banner");
 exit(0);
}

#code

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:8022);
if (!get_port_state(port)) exit(0);

banner = get_http_banner( port:port );
if ("Server: Ipswitch" >!< banner) exit(0);

req = http_get(item:"/NmConsole/Login.asp.", port:port);
r = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if( r == NULL )exit(0);

if (
  'SOFTWARE\\\\Ipswitch\\\\Network Monitor\\\\WhatsUp' >< r &&
  (
    '<%= app.GetDialogHeader("Log In") %>' >< r ||
    egrep(pattern:'<%( +if|@ +LANGUAGE="JSCRIPT")', string:r)
  )
) {
  security_message(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}
