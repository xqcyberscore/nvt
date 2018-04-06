# OpenVAS Vulnerability Test
# $Id: skullsplitter_html_injection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Skull-Splitter Guestbook Multiple HTML Injection Vulnerabilities
#
# Authors:
# Josh Zlatin-Amishav <josh at tkos dot co dot il>
#
# Copyright:
# Copyright (C) 2005 Josh Zlatin-Amishav
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

tag_summary = "The remote host is running the Skull-Splitter guestbook, a guestbook
written in PHP.
The remote version of this software is vulnerable to cross-site
scripting attacks. Inserting special characters into the subject
or message content can cause arbitrary code execution for third
party users, thus resulting in a loss of integrity of their 
system.";

tag_solution = "None at this time";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.18265");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_bugtraq_id(13632);
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_name("Skull-Splitter Guestbook Multiple HTML Injection Vulnerabilities");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Web application abuses");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

foreach dir( make_list_unique( "/guestbook", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + "/guestbook.php";
  res = http_get_cache(item:url, port:port);
  if ( res == NULL ) continue;

  if( egrep(pattern:"Powered by.*Skull-Splitter's PHP Guestbook ([0-1]\..*|2\.[0-2][^0-9])", string:res) ) {
    security_message( port:port );
    exit(0);
  }
}

exit( 99 );