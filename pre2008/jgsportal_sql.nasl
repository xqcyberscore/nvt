# OpenVAS Vulnerability Test
# $Id: jgsportal_sql.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: JGS-Portal Multiple XSS and SQL injection Vulnerabilities
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

tag_summary = "The remote host is running the JGS-Portal, a web portal written in PHP.

The remote version of this software contains an input validation flaw leading
multiple SQL injection and XSS vulnerabilities. An attacker may exploit these 
flaws to execute arbirtrary SQL commands against the remote database and to 
cause arbitrary code execution for third party users.";

tag_solution = "Unknown at this time";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18289");
 script_version("$Revision: 9348 $");
 script_cve_id("CVE-2005-1635", "CVE-2005-1633");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(13650);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("JGS-Portal Multiple XSS and SQL injection Vulnerabilities");
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
if ( ! can_host_php(port:port) ) exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/jgs_portal_statistik.php?meinaction=themen&month=1&year=1'";
  req = http_get(item:url, port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) continue;

  if (("SQL-DATABASE ERROR" >< res ) && ("SELECT starttime FROM bb1_threads WHERE FROM_UNIXTIME" >< res )) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );