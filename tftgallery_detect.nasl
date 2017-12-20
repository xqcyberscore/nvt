###############################################################################
# OpenVAS Vulnerability Test
# $Id: tftgallery_detect.nasl 8168 2017-12-19 07:30:15Z teissa $
#
# TFT Gallery Detection
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

tag_summary = "This host is running TFT Gallery, an easy-to-use image gallery
using PHP.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100324");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8168 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-19 08:30:15 +0100 (Tue, 19 Dec 2017) $");
 script_tag(name:"creation_date", value:"2009-10-29 12:31:54 +0100 (Thu, 29 Oct 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("TFT Gallery Detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.tftgallery.org");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100324";
SCRIPT_DESC = "TFT Gallery Detection";

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/gallery", "/photos", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/index.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if(egrep(pattern: '<meta name="generator" content="(TFT Gallery|TFTgallery)', string: buf, icase: TRUE))
 {
    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "(TFT Gallery|TFTgallery) ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[2]) ) {
       vers=chomp(version[2]);
    }

    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/tftgallery"), value: tmp_version);
  
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:tftgallery:tftgallery:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    info = string("TFT Gallery Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
