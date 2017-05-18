###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_unprotected_arris_2307.nasl 5842 2017-04-03 13:15:19Z cfi $
#
# ARRIS 2307 Unprotected Web Console
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

tag_summary = "The remote ARRIS 2307 Web Console is not protected by a password.";

tag_solution = "Set a password.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103703");
 script_version ("$Revision: 5842 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

 script_name("ARRIS 2307 Unprotected Web Console");

 script_xref(name:"URL" , value: "http://www.arrisi.com/");

 script_tag(name:"last_modification", value:"$Date: 2017-04-03 15:15:19 +0200 (Mon, 03 Apr 2017) $");
 script_tag(name:"creation_date", value:"2013-04-23 12:01:48 +0100 (Tue, 23 Apr 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default: 80);

host = http_host_name(port:port);
                                                                  
url = '/login.html';
res = http_get_cache(item:url, port:port);

if( 'content="ARRIS 2307"' >< res ) {

  login = "page=&logout=&action=submit&pws=";
  len = strlen(login);  

  req = string("POST /login.cgi HTTP/1.1\r\n",
               "Host: ", host,"\r\n",
               "User-Agent: ", OPENVAS_HTTP_USER_AGENT,"\r\n",
               "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
               "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
               "Accept-Encoding: identity\r\n",
               "DNT: 1\r\n",
               "Connection: keep-alive\r\n",
               "Referer: http://",host,"/login.html\r\n",
               "Content-Type: application/x-www-form-urlencoded\r\n",
               "Content-Length: ", len,"\r\n",
               "\r\n",
               login);

  result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if("lan_ipaddr" >< result && "http_passwd" >< result && "userNewPswd" >< result) {
    security_message(port:port);
    exit(0);
  }  

  exit(99);

}  

exit(0);
