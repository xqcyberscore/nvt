# OpenVAS Vulnerability Test
# $Id: xaraya_detection.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: Detects Xaraya version
#
# Authors:
# Josh Zlatin-Amishav
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

tag_summary = "The remote web server contains a web application framework written in
PHP. 

Description :

This script detects whether the remote host is running Xaraya and
extracts the version number and location if found. 

Xaraya is an extensible, open-source web application framework written
in PHP.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.19426");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9348 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Detects Xaraya version");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 script_family("Web application abuses");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_xref(name : "URL" , value : "http://www.xaraya.com/");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port)) exit(0);

foreach dir( make_list_unique( "/xaraya", cgi_dirs( port:port ) ) ) {

 if (dir == "") dir = "/";
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 if (res == NULL) continue;

 if (
   # Cookie from Xaraya
   "^Set-Cookie: XARAYASID=" >< res ||
   # Meta tag from Xaraya
   "^X-Meta-Generator: Xaraya ::" >< res ||
   # Xaraya look-and-feel
   egrep(string:res, pattern:'div class="xar-(alt|block-.+|menu-.+|norm)"')
 ) {

   # Look for the version number in a meta tag.
   pat = 'meta name="Generator" content="Xaraya :: ([^"]+)';
   matches = egrep(pattern:pat, string:res);
   if (matches) {
     foreach match (split(matches))
     {
       ver = eregmatch(pattern:pat, string:match);
       if (!isnull(ver))
       {
         ver = ver[1];
         info = string("Xaraya version ", ver, " is installed on the remote host\nunder the path ", dir, ".");
         break;
       }
     }
   }

   if (isnull(ver))
   {
     ver = "unknown";
     info = string("An unknown version of Xaraya is installed on the remote host\nunder the path ", dir, ".");
   }

   set_kb_item(
     name:string("www/", port, "/xaraya"),
     value:string(ver, " under ", dir)
   );

   report = '\n\nPlugin output :\n\n' + info;
   log_message(port:port, data:report);

   exit(0);
  }
}
