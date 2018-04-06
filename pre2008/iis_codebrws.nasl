# OpenVAS Vulnerability Test
# $Id: iis_codebrws.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Codebrws.asp Source Disclosure Vulnerability
#
# Authors:
# Matt Moore <matt@westpoint.ltd.uk>
# Majority of code from plugin fragment and advisory by H D Moore <hdm@digitaloffense.net>
#
# Copyright:
# Copyright (C) 2002 Matt Moore / HD Moore
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

tag_summary = "Microsoft's IIS 5.0 web server is shipped with a set of
sample files to demonstrate different features of the ASP
language. One of these sample files allows a remote user to
view the source of any file in the web root with the extension
.asp, .inc, .htm, or .html.";

tag_solution = "Remove the /IISSamples virtual directory using the Internet Services Manager. 
If for some reason this is not possible, removing the following ASP script will
fix the problem:

This path assumes that you installed IIS in c:\inetpub
        
c:\inetpub\iissamples\sdk\asp\docs\CodeBrws.asp";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10956");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-1999-0739");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 name = "Codebrws.asp Source Disclosure Vulnerability";
 script_name(name);
 

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore / HD Moore");
 family = "Web Servers";
 script_family(family);
 script_dependencies("find_service.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Check simpy tests for presence of Codebrws.asp. Could be improved
# to use the output of webmirror.nasl, and actually exploit the vulnerability.

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);


req = http_get(item:"/iissamples/sdk/asp/docs/codebrws.asp", port:port);
res = http_keepalive_send_recv(data:req, port:port);
if ("View Active Server Page Source" >< res)
{
    security_message(port);
}
