# OpenVAS Vulnerability Test
# $Id: cern_httpd_access_ctrl.nasl 8023 2017-12-07 08:36:26Z teissa $
# Description: CERN HTTPD access control bypass
#
# Authors:
# Michel Arboi
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

tag_summary = "It is possible to access protected web pages 
by changing / with // or /./
This was a bug in old versions of CERN web server

A work around consisted in rejecting patterns like:
//*
*//*
/./* 
*/./*";

tag_solution = "Upgrade your web server or tighten your filtering rules";

if(description)
{
 script_id(17230);
 script_version("$Revision: 8023 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-07 09:36:26 +0100 (Thu, 07 Dec 2017) $");
 script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
 
 name = "CERN HTTPD access control bypass";
 script_name(name);
 


 
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright("This script is Copyright (C) 2005 Michel Arboi");
 family = "Web Servers";
 script_family(family);
 script_dependencies("find_service.nasl", "http_version.nasl",
 "webmirror.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if (! get_port_state(port)) exit(0);

no404 = get_kb_item(strcat('www/no404/', port));

function check(port, loc)
{
 local_var	req, res;
 req = http_get(item:loc, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if (isnull(res)) exit(0);
 if (res =~ "^HTTP/[0-9]\.[0-9] +40[13]") return 403;
 else if (res =~ "^HTTP/[0-9]\.[0-9] +200 ")
 {
   if (no404 && no404 >< res) return 404;
   else return 200;
 }
 else return;
}

dirs = get_kb_list(strcat("www/", port, "/content/auth_required"));
if (isnull(dirs)) exit(0);

foreach dir (dirs)
{
  if (check(port: port, loc: dir) == 403)
  {
    foreach pat (make_list("//", "/./"))
    {
      dir2 = ereg_replace(pattern: "^/", replace: pat, string: dir);
      if (check(port: port, loc: dir2) == 200)
      {
        debug_print('>', dir2, '< can be read on ', get_host_name(),
	':', port, '\n');
        security_message(port: port);
        exit(0);
      }

      dir2 = ereg_replace(pattern: "^(.+)/", replace: "\\1"+pat, string: dir);
      if (check(port: port, loc: dir2) == 200)
      {
        debug_print('>', dir2, '< can be read on ', get_host_name(),
	':', port, '\n');
        security_message(port: port);
        exit(0);
      }
    }
  }
}
