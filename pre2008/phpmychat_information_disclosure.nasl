# OpenVAS Vulnerability Test
# $Id: phpmychat_information_disclosure.nasl 6056 2017-05-02 09:02:50Z teissa $
# Description: phpMyChat Information Disclosure
#
# Authors:
# Noam Rathaus
#
# Copyright:
# Copyright (C) 2004 Noam Rathaus
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

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.16056");
 script_version("$Revision: 6056 $");
 script_tag(name:"last_modification", value:"$Date: 2017-05-02 11:02:50 +0200 (Tue, 02 May 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_name("phpMyChat Information Disclosure");
 
 script_category(ACT_ATTACK);
 
 script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
 script_family("Web application abuses");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_xref(name : "URL" , value : "http://www.securiteam.com/unixfocus/6D00S0KC0S.html");
 
 script_tag(name : "summary" , value : "phpMyChat is an easy-to-install, easy-to-use multi-room
 chat based on PHP and a database, supporting MySQL,
 PostgreSQL, and ODBC.

 This set of script may allow an attacker to cause an information
 disclosre vulnerability allowing an attacker to cause the
 program to reveal the SQL username and password, the phpMyChat's
 administrative password, and other sensitive information.");

 script_tag(name:"qod_type", value:"remote_app");
 exit(0);
}

#
# The script code starts here
#

debug = 0;

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

dirs = make_list_unique(cgi_dirs(port:port), "/forum", "/forum/chat", "/chat", "/chat/chat", "/"); # The /chat/chat isn't a mistake

foreach dir (dirs) {

  if( dir == "/" ) dir = "";

  if (debug) { display("dir: ", dir, "\n"); }

  req = http_get(item: dir + "/setup.php3?next=1", port:port);
  r = http_keepalive_send_recv(port:port, data:req, bodyonly: 1);
  if( r == NULL )exit(0);

  if (debug) { display("r: [", r, "]\n"); }

  if(("C_DB_NAME" >< r) || ("C_DB_USER" >< r) || ("C_DB_PASS" >< r)) {
    security_message(port:port);
    exit(0);
 }
}

exit(99);