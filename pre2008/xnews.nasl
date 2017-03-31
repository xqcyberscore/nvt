# OpenVAS Vulnerability Test
# $Id: xnews.nasl 3362 2016-05-20 11:19:10Z antu123 $
# Description: x-news 1
#
# Authors:
# Audun Larsen <larsen@xqus.com>
#
# Copyright:
# Copyright (C) 2004 Audun Larsen
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
information disclosure. 

Description :

X-News is a news management system, written in PHP.  X-News uses a
flat-file database to store information.  It will run on most Unix and
Linux variants, as well as Microsoft Windows operating systems. 

X-News stores user ids and passwords, as MD5 hashes, in a world-
readable file, 'db/users.txt'.  This is the same information that is
issued by X-News in cookie-based authentication credentials.  An
attacker may incorporate this information into cookies and then submit
them to gain unauthorized access to the X-News administrative account.";

tag_solution = "Deny access to the files in the 'db' directory through the webserver.";

if(description)
{
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_id(12068);
 script_version("$Revision: 3362 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-20 13:19:10 +0200 (Fri, 20 May 2016) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_cve_id("CVE-2002-1656");
 script_bugtraq_id(4283);
 name = "x-news 1";
 script_name(name);

 summary = "Check if version of x-news 1.x is installed";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
 script_copyright("This script is Copyright (C) 2004 Audun Larsen");
 family = "Web application abuses";
 script_family(family);
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_dependencies("http_version.nasl");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.ifrance.com/kitetoua/tuto/x_holes.txt");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);


dirs = make_list("/x-news", "/x_news", "/xnews", "/news", cgi_dirs());

foreach dir (dirs) {
 req = http_get(item:string(dir, "/x_news.php"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if( res == NULL ) exit(0);

 if("Powered by <a href='http://www.xqus.com'>x-news</a> v.1\.[01]" >< res)
 {
   req2 = http_get(item:string(dir, "/db/users.txt"), port:port);
   res2 = http_keepalive_send_recv(port:port, data:req2, bodyonly:TRUE);
   if( res2 == NULL ) exit(0);
   if("|1" >< res2)
   {
      security_message(port);
      exit(0);
   } 
  } 
}
