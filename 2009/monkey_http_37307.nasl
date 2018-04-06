###############################################################################
# OpenVAS Vulnerability Test
# $Id: monkey_http_37307.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Monkey HTTP Daemon Invalid HTTP 'Connection' Header Denial Of Service Vulnerability
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

tag_summary = "Monkey HTTP Daemon is prone to a denial-of-service vulnerability.

Remote attackers can exploit this issue to cause the application to
crash, denying service to legitimate users.

Versions prior to Monkey HTTP Daemon 0.9.3 are vulnerable.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100397");
 script_version("$Revision: 9350 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-12-15 19:11:56 +0100 (Tue, 15 Dec 2009)");
 script_bugtraq_id(37307);
 script_tag(name:"cvss_base", value:"7.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

 script_name("Monkey HTTP Daemon Invalid HTTP 'Connection' Header Denial Of Service Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/37307");
 script_xref(name : "URL" , value : "http://groups.google.com/group/monkeyd/browse_thread/thread/055b4e9b83973861/c0e013d166ae1eb3?show_docid=c0e013d166ae1eb3");
 script_xref(name : "URL" , value : "http://monkeyd.sourceforge.net/");
 script_xref(name : "URL" , value : "http://census-labs.com/news/2009/12/14/monkey-httpd/");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/508442");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("Monkey/banner");
 script_require_ports("Services/www", 2001);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}


include("http_func.inc");
include("version_func.inc");

port = get_http_port(default:2001);
if(!get_port_state(port))exit(0);

banner = get_http_banner(port: port);
if(!banner)exit(0);

if("Server: Monkey/" >!< banner)exit(0);
version = eregmatch(pattern: "Server: Monkey/([0-9.]+)", string: banner);
if(isnull(version[1]))exit(0);

   if(version_is_less(version: version[1], test_version: "0.9.3")) {
        security_message(port:port);
        exit(0); 
   }

exit(0);

