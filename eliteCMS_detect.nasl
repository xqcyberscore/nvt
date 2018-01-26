###############################################################################
# OpenVAS Vulnerability Test
# $Id: eliteCMS_detect.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# eliteCMS Detection
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

tag_summary = "This host is running eliteCMS a free, PHP and MySQL driven
  Content Management System.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100221");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8528 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
 script_tag(name:"creation_date", value:"2009-06-14 17:19:03 +0200 (Sun, 14 Jun 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("eliteCMS Detection");  
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://elitecms.elite-graphix.net/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100221";
SCRIPT_DESC = "eliteCMS Detection";

port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir( make_list_unique( "/cms", "/elite", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/admin/login.php";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if(egrep(pattern: 'Elite CMS .* Admin Control Panel', string: buf, icase: TRUE) ||
    egrep(pattern: 'eliteCMS - The Lightweight CMS', string: buf, icase: TRUE)   ||
    egrep(pattern: 'Pow(o|e)red by <a [^>]+>Elite CMS', string: buf, icase: TRUE) )
 { 
    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "Version ([0-9.]+)",icase:TRUE);
    
    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    } 
    
    tmp_version = string(vers," under ",install);
    set_kb_item(name: string("www/", port, "/eliteCMS"), value: tmp_version);
   
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tmp_version, exp:"^([0-9.]+)", base:"cpe:/a:elitecms:elitecms:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

    info = string("\n\neliteCMS Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n"); 

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
