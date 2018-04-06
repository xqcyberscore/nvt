# OpenVAS Vulnerability Test
# $Id: oracle9i_XSQLServlet_XSQLConfig.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Oracle XSQLServlet XSQLConfig.xml File
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

tag_summary = "It is possible to read the contents of the XSQLConfig.xml file which contains 
sensitive information.";

tag_solution = "Move this file to a safer location and update your servlet engine's 
configuration file to reflect the change.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.10855");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4290);
 script_cve_id("CVE-2002-0568");
 script_tag(name:"cvss_base", value:"2.1");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
 name = "Oracle XSQLServlet XSQLConfig.xml File";
 script_name(name);
 
 script_xref(name : "URL" , value : "http://www.nextgenss.com/papers/hpoas.pdf");
 script_xref(name : "URL" , value : "http://www.oracle.com/");

 
 
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_active");
 
 script_copyright("This script is Copyright (C) 2002 Matt Moore");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);

 req = http_get(item:"/xsql/lib/XSQLConfig.xml",
 		port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 tip = string("On a PRODUCTION system, under no circumstances should this confi
guration file reside in a directory that is browseable through the virtual path
 of your web server.");

if(tip >< r)
 {
 http_close_socket(soc);
 security_message(port);
 }
else
 {
 req = http_get(item:"/servlet/oracle.xml.xsql.XSQLServlet/xsql/lib/XSQLConfig.xml", port:port);
 soc = http_open_socket(port);
 if(soc)
  {
  send(socket:soc, data:req);
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(tip >< r)	
 	security_message(port);

   }
  }
 }
