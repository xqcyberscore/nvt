###############################################################################
# OpenVAS Vulnerability Test
# $Id: OpenX_detect.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# OpenX Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100363";

tag_summary =
"The script sends a connection request to the server and attempts to
extract the version number from the reply.";

if(description)
{
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9584 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
 script_tag(name:"creation_date", value:"2009-11-25 11:49:08 +0100 (Wed, 25 Nov 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"qod_type", value:"remote_banner");
 script_tag(name : "summary" , value : tag_summary);
 script_name("OpenX Detection");
 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/openx", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = string(dir, "/www/admin/index.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: "<title>OpenX</title>", string: buf, icase: TRUE) ||
    egrep(pattern: "Welcome to OpenX", string: buf, icase: TRUE)     ||
    egrep(pattern: 'meta name="generator" content="OpenX', string: buf, icase: TRUE)) {

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "OpenX v([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/openx"), value: tmp_version);
    set_kb_item(name:"openx/installed", value:TRUE);

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:openx:openx:");
    if(isnull(cpe))
      cpe = 'cpe:/a:openx:openx';

    register_product(cpe:cpe, location:install, port:port);

    log_message(data: build_detection_report(app:"OpenX",
                                             version:vers,
                                             install:install,
                                             cpe:cpe,
                                             concluded: version[0]),
                                             port:port);

 }
}

exit(0);
