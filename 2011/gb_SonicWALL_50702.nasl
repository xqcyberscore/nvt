###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_SonicWALL_50702.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# SonicWALL Aventail 'CategoryID' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "SonicWALL Aventail is prone to an SQL-injection vulnerability because
the application fails to properly sanitize user-supplied input before
using it in an SQL query.

A successful exploit may allow an attacker to compromise the
application, access or modify data, or exploit vulnerabilities in the
underlying database.

Further research conducted by the vendor indicates this issue may not
be a vulnerability affecting the application.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103342");
 script_bugtraq_id(50702);
 script_cve_id("CVE-2011-5262");
 script_version ("$Revision: 9351 $");
 script_name("SonicWALL Aventail 'CategoryID' Parameter SQL Injection Vulnerability");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50702");
 script_xref(name : "URL" , value : "http://www.sonicwall.com/us/products/EX_Series.html");

 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-11-21 09:56:06 +0100 (Mon, 21 Nov 2011)");
 script_tag(name:"qod_type", value:"remote_active");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/prodpage.cfm?CFID=&CFTOKEN=&CategoryID='openvas"); 

  if(http_vuln_check(port:port, url:url,pattern:"ODBC Error",  extra_check:"AND Products.CategoryID = ''openvas")) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
