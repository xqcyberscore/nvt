###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_axis_detect.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# Axis Commerce Detection
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

tag_summary = "This host is running Axis Commerce, an open source eCommerce solution.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103223");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8528 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
 script_tag(name:"creation_date", value:"2011-08-24 15:44:33 +0200 (Wed, 24 Aug 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Axis Commerce Detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://axiscommerce.com/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/axis", "/shop", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/admin/index.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL )continue;

 if(egrep(pattern: "<title>Login to Axis administrator panel", string: buf, icase: TRUE) &&
    "Powered by Axis" >< buf) {

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "Powered by Axis v. ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/axis_ecommerce"), value: string(vers," under ",install));

    info = string("Axis Commerce Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
