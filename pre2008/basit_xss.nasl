# OpenVAS Vulnerability Test
# $Id: basit_xss.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Basit cms Cross Site Scripting Bugs
#
# Authors:
# K-Otik.com <ReYn0@k-otik.com>
#
# Copyright:
# Copyright (C) 2003 k-otik.com
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

tag_summary = "The remote web server contains a PHP script which is vulnerable to a 
cross site scripting and SQL injection issue.

Description :

Basit cms  1.0 has a cross site scripting bug. An attacker may use it to
perform a cross site scripting attack on this host.

In addition to this, it is vulnerable to a SQL insertion
attack which may allow an attacker to get the control
of your database.";

tag_solution = "Upgrade to a newer version.";

#  Message-ID: <1642444765.20030319015935@olympos.org>
#  From: Ertan Kurt <mailto:ertank@olympos.org>
#  To: <bugtraq@securityfocus.com>
#  Subject: Some XSS vulns

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.11445");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(7139);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_name("Basit cms Cross Site Scripting Bugs");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2003 k-otik.com");
 script_dependencies("find_service.nasl", "http_version.nasl", "cross_site_scripting.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir, "/modules/Submit/index.php?op=pre&title=<script>window.alert(document.cookie);</script>");

  if(http_vuln_check(port:port, url:url,pattern:"<script>window\.alert\(document\.cookie\);</script>",check_header:TRUE)) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );