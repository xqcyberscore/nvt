# OpenVAS Vulnerability Test
# $Id: mailgust_sql_injection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: MailGust SQL Injection Vulnerability
#
# Authors:
# Ferdy Riphagen <f.riphagen@nsec.nl>
#
# Copyright:
# Copyright (C) 2005 Ferdy Riphagen
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

tag_summary = "The remote web server contains a PHP script that is prone to SQL
injection attacks. 

Description :

The remote host appears to be running MailGust, a mailing list
manager, newsletter distribution tool and message board. 

A vulnerability was identified in MailGust, which may be exploited by
remote attackers to execute arbitrary SQL commands.";

tag_solution = "Unknown at this time.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.19947");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2005-3063");
  script_bugtraq_id(14933);
  script_name("MailGust SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2005 Ferdy Riphagen");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://retrogod.altervista.org/maildisgust.html");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/mailgust", "/forum", "/maillist", "/gust", cgi_dirs( port:port ) ) ) {

 if( dir == "/" ) dir = "";
 # Make sure the affected script exists.
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 if (res == NULL) continue;

 if (egrep(pattern:">Powered by <a href=[^>]+>Mailgust", string:res)) {

  host = http_host_name( port:port );

  req = string(
  "POST ",dir,"/index.php HTTP/1.0\r\n",
  "Host: ", host, "\r\n",
  "Content-Length: 64\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
  "method=remind_password&list=maillistuser&email='&showAvatar=\r\n\r\n");

  recv = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(recv == NULL) continue;

  if(egrep(pattern: "SELECT.*FROM.*WHERE", string:recv)) {
   security_message(port);
   exit(0);
  }
 }
}

exit( 99 );