###############################################################################
# OpenVAS Vulnerability Test
# $Id: novaboard_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
#
# NovaBoard Detection
#
# Authors:
# Michael Meyer
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

tag_summary = "This host is running NovaBoard, an Open Source forum solution.";

if (description)
{
 script_id(100477);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2010-01-29 17:41:41 +0100 (Fri, 29 Jan 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("NovaBoard Detection");

 script_summary("Checks for the presence of NovaBoard");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.novaboard.net/");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/novaboard","/forum","/board",cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/index.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: "Powered By NovaBoard", string: buf, icase: TRUE))
 {
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "Powered by <a [^>]+>NovaBoard v([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/NovaBoard"), value: string(vers," under ",install));

    info = string("NovaBoard Version '");
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

