# OpenVAS Vulnerability Test
# $Id: xaraya_detection.nasl 3398 2016-05-30 07:58:00Z antu123 $
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

 desc = "
 Summary:
 " + tag_summary;


if(description)
{
 script_id(19426);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 3398 $");
 script_tag(name:"last_modification", value:"$Date: 2016-05-30 09:58:00 +0200 (Mon, 30 May 2016) $");
 script_tag(name:"creation_date", value:"2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)");
 script_tag(name:"cvss_base", value:"0.0");
 name = "Detects Xaraya version";
 script_name(name);
 
 summary = "Xaraya detection";
 script_summary(summary);
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_copyright("Copyright (C) 2005 Josh Zlatin-Amishav");
 family = "Web application abuses";
 script_family(family);
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_xref(name : "URL" , value : "http://www.xaraya.com/");
 script_tag(name : "summary" , value : tag_summary);
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
if(!can_host_php(port:port)) exit(0);


dirs = make_list("/xaraya", cgi_dirs());

foreach dir (dirs)
{
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 #display("res[", res, "]\n");
 if (res == NULL) exit(0);

 if (
   # Cookie from Xaraya
   "^Set-Cookie: XARAYASID=" >< res ||
   # Meta tag from Xaraya
   "^X-Meta-Generator: Xaraya ::" >< res ||
   # Xaraya look-and-feel
   egrep(string:res, pattern:'div class="xar-(alt|block-.+|menu-.+|norm)"')
 ) {
   if (dir == "") dir = "/";

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

   desc += '\n\nPlugin output :\n\n' + info;
   log_message(port:port, data:desc);

   exit(0);
  }
}
