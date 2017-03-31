###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_viewheadline.php_sql_inj_01_15.nasl 2748 2016-02-29 10:19:10Z benallard $
#
# viewheadline.php SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105186");
 script_version ("$Revision: 2748 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("viewheadline.php SQL Injection Vulnerability");

 script_tag(name: "impact" , value:"Exploiting this issue could allow an attacker to compromise the
application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

 script_tag(name: "vuldetect" , value:"Send a special crafted HTTP GET request and check the response");

 script_tag(name: "summary" , value:"viewheadline.php is prone to an SQL-injection vulnerability because it
fails to sufficiently sanitize user-supplied data before using it in an SQL query.");

 script_tag(name:"last_modification", value:"$Date: 2016-02-29 11:19:10 +0100 (Mon, 29 Feb 2016) $");
 script_tag(name:"creation_date", value:"2015-01-26 11:22:03 +0100 (Mon, 26 Jan 2015)");
 script_summary("Check for SQL injection");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("phpgroupware_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name:"qod_type", value:"remote_app");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

dirs = make_list_unique( cgi_dirs(), "/about", "/foundation" );

if( dir = get_app_location( cpe:"cpe:/a:phpgroupware:phpgroupware", port:port ) )  dirs = make_list_unique( dir, dirs );

foreach dir ( dirs )
{

  if( dir == "/" ) dir = "";

  url = dir + "/viewheadline.php?id=-9%27%20union%20select%201,2,3,4,5,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23%20from%20wp_users--+";

  if( http_vuln_check( port:port, url:url, pattern:"OpenVAS-SQL-Injection-Test" ) )
  {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit(0);
  }
}

exit(99);
