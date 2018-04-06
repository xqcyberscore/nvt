# OpenVAS Vulnerability Test
# $Id: wowBB_sql_injection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: WowBB view_user.php SQL Injection Flaw
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
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

tag_summary = "The remote web server contains a PHP script that is affected by
a SQL injection flaw.

Description :

The remote host is running WowBB, a web-based forum written in PHP. 

The remote version of this software is vulnerable to SQL injection
attacks through the script 'view_user.php'.  A malicious user can
exploit this issue to manipulate database queries, resulting in
disclosure of sensitive information, attacks against the underlying
database, and the like.";

tag_solution = "Unknown at this time.";

# Ref: Megasky <magasky@hotmail.com>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18221");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2005-1554");
  script_bugtraq_id(13569);
  script_xref(name:"OSVDB", value:"16543");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WowBB view_user.php SQL Injection Flaw");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/399637");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/forum", "/forums", "/board", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = string(dir,"/view_user.php?list=1&letter=&sort_by='select");

  buf = http_get(item:url, port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:TRUE);
  if( r == NULL ) continue;

  if ("Invalid SQL query: SELECT" >< r && 'TITLE="WowBB Forum Software' >< r) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );