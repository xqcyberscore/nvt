# OpenVAS Vulnerability Test
# $Id: mailgust_sql_injection.nasl 3359 2016-05-19 13:40:42Z antu123 $
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

if (description) {
script_id(19947);
script_version("$Revision: 3359 $");
script_tag(name:"last_modification", value:"$Date: 2016-05-19 15:40:42 +0200 (Thu, 19 May 2016) $");
script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
script_tag(name:"cvss_base", value:"7.5");
script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
script_cve_id("CVE-2005-3063");
script_bugtraq_id(14933);

name = "MailGust SQL Injection Vulnerability";
script_name(name);

summary = "Check if MailGust is vulnerable to SQL Injection.";
script_summary(summary);

script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
script_family("Web application abuses");

script_copyright("This script is Copyright (C) 2005 Ferdy Riphagen");

script_dependencies("http_version.nasl");
script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

script_tag(name : "solution" , value : tag_solution);
script_tag(name : "summary" , value : tag_summary);
script_xref(name : "URL" , value : "http://retrogod.altervista.org/maildisgust.html");
exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

dirs = make_list("/mailgust", "/forum", "/maillist", "/gust", cgi_dirs());

foreach dir (dirs)
{
 # Make sure the affected script exists.
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 if (res == NULL) exit(0);

 if (egrep(pattern:">Powered by <a href=[^>]+>Mailgust", string:res)) {
  req = string(
  "POST ",dir,"/index.php HTTP/1.0\r\n",
  "Host: ", get_host_name(), "\r\n",
  "Content-Length: 64\r\n",
  "Content-Type: application/x-www-form-urlencoded\r\n\r\n",
  "method=remind_password&list=maillistuser&email='&showAvatar=\r\n\r\n");

  recv = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
  if(recv == NULL)exit(0);
  debug_print(recv);

  if(egrep(pattern: "SELECT.*FROM.*WHERE", string:recv))
  {
   security_message(port);
   exit(0);
  }
 }
}
