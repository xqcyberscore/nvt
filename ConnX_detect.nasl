###############################################################################
# OpenVAS Vulnerability Test
# $Id: ConnX_detect.nasl 5723 2017-03-24 15:46:34Z cfi $
#
# ConnX Detection
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

tag_summary = "This host is running ConnX.";

if (description)
{
 script_id(100114);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5723 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-24 16:46:34 +0100 (Fri, 24 Mar 2017) $");
 script_tag(name:"creation_date", value:"2009-04-08 20:52:50 +0200 (Wed, 08 Apr 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("ConnX Detection");  
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("General");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.q2solutions.com.au");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);
if(!can_host_asp(port:port))exit(0);

foreach dir( make_list_unique( "/", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = dir + "/";
 buf = http_get_cache( item:url, port:port );
 if( buf == NULL ) continue;

 if(egrep(pattern: "Login to ConnX", string: buf, icase: TRUE) && egrep(pattern: "Q2 Solutions", string: buf, icase: TRUE))
 { 

    vers = string("unknown");

    ### try to get version 
    version = eregmatch(string: buf, pattern: "Version ([0-9.]+ [^<]*)",icase:TRUE);
    
    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    } 
    
    set_kb_item(name: string("www/", port, "/connx"), value: string(vers," under ",install));

    info = string("\n\nConnX Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n"); 

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
