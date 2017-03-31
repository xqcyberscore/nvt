###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_scrutinizer_detect.nasl 5044 2017-01-19 17:35:30Z mime $
#
# Scrutinizer Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

tag_summary = "Detection of Scrutinizer
                    
The script sends a connection request to the server and attempts to
extract the version number from the reply.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103532";   

if (description)
{
 
 script_tag(name:"cvss_base", value:"0.0");
 script_oid(SCRIPT_OID);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5044 $");
 script_tag(name:"last_modification", value:"$Date: 2017-01-19 18:35:30 +0100 (Thu, 19 Jan 2017) $");
 script_tag(name:"creation_date", value:"2012-08-08 12:07:31 +0200 (Wed, 08 Aug 2012)");
 script_name("Scrutinizer Detection");
 script_summary("Checks for the presence of Scrutinizer");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list(cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/index.html");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: "<title>Scrutinizer</title>", string: buf, icase: TRUE) )
 {display(buf);
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "<div id='testAlertDivTitle'>Scrutinizer ([0-9.]+)</div>",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/scrutinizer"), value: string(vers," under ",install));
    set_kb_item(name:"scrutinizer/installed", value:TRUE);

    cpe = build_cpe(value:vers, exp:"^([0-9.]+)", base:"cpe:/a:dell:sonicwall_scrutinizer:");
    if(isnull(cpe))
      cpe = 'cpe:/a:dell:sonicwall_scrutinizer';

    register_product(cpe:cpe, location:install, nvt:SCRIPT_OID, port:port);

    log_message(data: build_detection_report(app:"Scrutinizer", version:vers, install:install, cpe:cpe, concluded: version[0]),
                port:port);

    exit(0);

 }
}
exit(0);
