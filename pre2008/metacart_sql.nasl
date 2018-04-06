# OpenVAS Vulnerability Test
# $Id: metacart_sql.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: MetaCart E-Shop ProductsByCategory.ASP SQL and XSS Injection Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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

tag_summary = "The remote host is running the MetaCart e-Shop, an online store written in ASP.

Due to a lack of user input validation, the remote version of this software is vulnerable
to various SQL injection vulnerabilities and cross site scripting attacks.

An attacker may exploit these flaws to execute arbitrary SQL commands against the remote
database or to perform a cross site scripting attack using the remote host.";

tag_solution = "None at this time";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18290");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(13385, 13384, 13383, 13382, 13639);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("MetaCart E-Shop ProductsByCategory.ASP SQL and XSS Injection Vulnerabilities");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_asp(port:port) ) exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port )) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/productsByCategory.asp?intCatalogID=3'&strCatalog_NAME=OpenVAS";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) continue;

  # Check for the SQL injection
  if ("80040e14" >< res && "cat_ID = 3'" >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );