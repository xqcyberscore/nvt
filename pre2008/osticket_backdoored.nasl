# OpenVAS Vulnerability Test
# $Id: osticket_backdoored.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: osTicket Backdoored
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

tag_summary = "There is a vulnerability in the current version of osTicket
that allows an attacker to upload an PHP script, and then access it
causing it to execute.
This attack is being actively exploited by attackers to take over
servers. This script tries to detect infected servers.";

tag_solution = "1) Remove any PHP files from the /attachments/ directory.
2) Place an index.html file there to prevent directory listing of that
directory.
3) Upgrade osTicket to the latest version.";

# From: Guy Pearce <dt_student@hotmail.com>
# Date: 21.6.2004 08:01
# Subject: Multiple osTicket exploits!

# This script detects those osTicket systems that were backdoored,
# not the vulnerability

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12649");
  script_version("$Revision: 9348 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:01:19 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("osTicket Backdoored");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2004 Noam Rathaus");
  script_family("Web application abuses");
  script_dependencies("osticket_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("osticket/installed");

  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! can_host_php(port:port) ) exit(0);
if ( ! get_kb_item("www/" + port + "/osticket" )  ) exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  req = http_get(item:dir +  "/attachments/", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) continue;

  if ("[DIR]" >< res) {
  # There is a directory there, so directory listing worked
  v = eregmatch(pattern: '<A HREF="([^"]+.php)">', string:res);
  if (isnull(v)) return;
  req = http_get(item:string(dir, "/attachments/", v[1]), port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if ( res == NULL ) continue;
  if ("PHP Shell" >< res || "<input type = 'text' name = 'cmd' value = '' size = '75'>" >< res ) {
    security_message(port: port);
    exit(0);
  }
 }
}
