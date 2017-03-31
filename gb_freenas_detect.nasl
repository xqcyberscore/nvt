###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freenas_detect.nasl 5390 2017-02-21 18:39:27Z mime $
#
# FreeNAS Detection
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

tag_summary = "This host is running FreeNAS, an embedded open source NAS
(Network-Attached Storage) distribution based on FreeBSD.";

if (description)
{
 
 script_id(100911);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5390 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 19:39:27 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-11-19 13:40:50 +0100 (Fri, 19 Nov 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("FreeNAS Detection");

 script_summary("Checks for the presence of FreeNAS");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_mandatory_keys("lighttpd/banner");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://freenas.org/");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100911";
SCRIPT_DESC = "FreeNAS Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

banner = get_http_banner(port:port);
if(!banner || "Server: lighttpd" >!< banner)exit(0);

dirs = make_list("/nas","/freenas",cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/login.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if("<title>FreeNAS" >< buf && "Username" >< buf && "Password" >< buf)
 {
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    vers = string("unknown");
    ### try to get version 

    url = string(dir, "/CHANGES");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    version = eregmatch(string: buf, pattern: "FreeNAS ([0-9bRC.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/freenas"), value: string(vers," under ",install));

    if(vers == "unknown") {
      register_host_detail(name:"App", value:string("cpe:/a:freenas:freenas"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    } else {
      register_host_detail(name:"App", value:string("cpe:/a:freenas:freenas:",vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    }  

    info = string("FreeNAS Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

       if(report_verbosity > 0) {
         log_message(port:port,data:info);
       }
       exit(0);

 }
}
exit(0);

