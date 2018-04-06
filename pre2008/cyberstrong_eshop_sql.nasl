# OpenVAS Vulnerability Test
# $Id: cyberstrong_eshop_sql.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Cyberstrong eShop SQL Injection Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
# Fixed by Tenable: - added See also.
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

tag_summary = "The remote host is running Cyberstrong eShop, a shopping cart written
in ASP.

The remote version of this software contains several input validation
flaws leading to SQL injection vulnerabilities.  An attacker may
exploit these flaws to affect database queries, possibly resulting in
disclosure of sensitive information (for example, the admin's user and
password) and attacks against the underlying database.";

tag_solution = "None at this time";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.19391");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_cve_id("CVE-2003-0509");
 script_bugtraq_id(14101, 14103, 14112);
 script_xref(name:"OSVDB", value:"10098");
 script_xref(name:"OSVDB", value:"10099");
 script_xref(name:"OSVDB", value:"10100");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Cyberstrong eShop SQL Injection Vulnerabilities");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_active");
 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2003-07/0006.html");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port)) exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/20Review.asp?ProductCode='";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if ( res == NULL ) continue;

  if ( 'Microsoft OLE DB Provider for ODBC Drivers' >< res && 'ORDER BY TypeID' >< res ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );