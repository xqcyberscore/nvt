###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpWebSite_detect.nasl 9580 2018-04-24 08:44:20Z jschulte $
#
# phpWebSite Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103106");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9580 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-24 10:44:20 +0200 (Tue, 24 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-03-04 13:25:07 +0100 (Fri, 04 Mar 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("phpWebSite Detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : "This host is running phpWebSite. phpWebSite provides a complete web
site content management system.");
 script_xref(name : "URL" , value : "http://phpwebsite.appstate.edu/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/phpwebsite", "/cms", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = string(dir,"/index.php?module=users&action=user&command=login_page");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if('<meta name="generator" content="phpWebSite" />' >< buf &&
    "User_Login_Main_phpws_username" >< buf)
 {

    vers = string("unknown");

    set_kb_item(name: string("www/", port, "/phpWebSite"), value: string(vers," under ",install));

    info = string("phpWebSite Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
