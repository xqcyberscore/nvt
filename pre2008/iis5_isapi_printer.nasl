# OpenVAS Vulnerability Test
# $Id: iis5_isapi_printer.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: IIS 5 .printer ISAPI filter applied
#
# Authors:
# Matt Moore <matt.moore@westpoint.ltd.uk>
# www.westpoint.ltd.uk
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Added link to the Bugtraq message archive
#
# Copyright:
# Copyright (C) 2001 Matt Moore
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

tag_summary = "Remote Web server supports Internet Printing Protocol

Description :

IIS 5 has support for the Internet Printing Protocol(IPP), which is 
enabled in a default install. The protocol is implemented in IIS5 as an 
ISAPI extension. At least one security problem (a buffer overflow)
has been found with that extension in the past, so we recommend
you disable it if you do not use this functionality.";

tag_solution = "To unmap the .printer extension:
 1.Open Internet Services Manager. 
 2.Right-click the Web server choose Properties from the context menu. 
 3.Master Properties 
 4.Select WWW Service -> Edit -> HomeDirectory -> Configuration 
and remove the reference to .printer from the list.";

if(description)
{
 script_id(10661);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"0.0");
 
 
 name = "IIS 5 .printer ISAPI filter applied";
 script_name(name);
 


 
 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_probe");
 
 script_copyright("This script is Copyright (C) 2001 Matt Moore");
 family = "Web Servers";
 script_family(family);
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("IIS/banner");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://online.securityfocus.com/archive/1/181109");
 exit(0);
}

# Actual check starts here...
# Check makes a request for NULL.printer

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);


sig = get_http_banner(port:port);
if ( sig && "IIS" >!< sig ) exit(0);

if(get_port_state(port))
{ 
 req = http_get(item:"/NULL.printer", port:port);
 r = http_keepalive_send_recv(port:port, data:req);
 if("Error in web printer install" >< r)	
 	log_message(port);

}
