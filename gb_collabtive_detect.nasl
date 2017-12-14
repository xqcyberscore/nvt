###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_collabtive_detect.nasl 8115 2017-12-14 07:30:22Z teissa $
#
# Collabtive Detection
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

tag_summary = "This host is running Collabtive, a Project Management and Open Source
Groupware.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100854");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8115 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-14 08:30:22 +0100 (Thu, 14 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-10-13 18:51:23 +0200 (Wed, 13 Oct 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Collabtive Detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://collabtive.o-dyn.de");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100854";
SCRIPT_DESC = "Collabtive Detection";

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/collabtive", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/index.ph";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if("Open Source project management" >< buf && "collabtive" >< buf && "<title>Login" >< buf)
 {
    vers = string("unknown");
    ### try to get version 

    url = string(dir, "/changelog.txt");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

    version = eregmatch(string: buf, pattern: "Collabtive ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);

    } else {

      url = string(dir, "/admin.php"); # not accurate. I saw 0.6.4 on admin.php while real version is 0.6.5
      req = http_get(item:url, port:port);
      buf = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

      version = eregmatch(string: buf, pattern: "Collabtive ([0-9.]+)",icase:TRUE);

      if ( !isnull(version[1]) ) {
        vers=chomp(version[1]); 
      }	
    }  

    set_kb_item(name: string("www/", port, "/collabtive"), value: string(vers," under ",install));

    if(vers == "unknown") {
      register_host_detail(name:"App", value:string("cpe:/a:collabtive:collabtive"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    } else {
      register_host_detail(name:"App", value:string("cpe:/a:collabtive:collabtive:",vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    }  

    info = string("Collabtive Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
