# OpenVAS Vulnerability Test
# $Id: uebimiau_session_disclosure.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: Uebimiau Session Directory Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus
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

# ITTS ADVISORE 01/05 - Uebimiau <= 2.7.2 Multiples Vulnerabilities
# Martin Fallon <mar_fallon@yahoo.com.br>
# 2005-01-27 14:09

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.16279");
 script_version("$Revision: 6056 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_name("Uebimiau Session Directory Disclosure");
 script_category(ACT_GATHER_INFO);
 script_copyright("This script is Copyright (C) 2005 Noam Rathaus");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "summary" , value : "UebiMiau is a simple and cross-plataform POP3/IMAP mail
 reader written in PHP.

 Uebimiau in default installation create one temporary folder 
 to store 'sessions' and other files. This folder is defined 
 in 'inc/config.php' as './database/'.

 If the web administrator don't change this folder, an attacker
 can exploit this using the follow request:
 http://server-target/database/_sessions/");
 script_tag(name : "solution" , value : "1) Insert index.php in each directory of the Uebimiau

 2) Set variable $temporary_directory to a directory 
 not public and with restricted access, set permission
 as read only to 'web server user' for each files in
 $temporary_directory.

 3) Set open_basedir in httpd.conf to yours clients follow  
 the model below:

 <Directory /server-target/public_html>
  php_admin_value open_basedir
  /server-target/public_html
 </Directory>");

 script_tag(name:"solution_type", value:"Workaround");
 script_tag(name:"qod_type", value:"remote_app");
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

function check(loc)
{

 if(loc == "/") loc = "";

 req = http_get(item:string(loc, "/database/_sessions/"), port:port);
 r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
 if( r == NULL )exit(0);

 if (( "Parent Directory" >< r) && ("/database/_sessions" >< r))
 {
  security_message(port:port);
  exit(0);
 }
}

foreach dir (make_list_unique("/", "/uebimiau-2.7.2", "/mailpop", "/webmail", cgi_dirs(port:port)))
{
 check(loc:dir);
}

exit(99);