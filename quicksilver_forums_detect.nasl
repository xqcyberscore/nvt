###############################################################################
# OpenVAS Vulnerability Test
# $Id: quicksilver_forums_detect.nasl 2837 2016-03-11 09:19:51Z benallard $
#
# Quicksilver Forums Detection
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

tag_summary = "This host is running Quicksilver Forums.";

if (description)
{
 script_id(100503);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2837 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:19:51 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2010-02-23 17:05:07 +0100 (Tue, 23 Feb 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Quicksilver Forums Detection");

 script_summary("Checks for the presence of Quicksilver Forums");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.quicksilverforums.com/");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100503";
SCRIPT_DESC = "Quicksilver Forums Detection";

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/forum","/board",cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/index.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: "Powered by <a [^>]+>Quicksilver Forums", string: buf, icase: TRUE))
 {
     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    vers = string("unknown");
    ### try to get version 
    url = string(dir, "/docs/CHANGES.txt");
    req = http_get(item:url, port:port);
    buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    version = eregmatch(string: buf, pattern: "Changes for ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
       register_host_detail(name:"App", value:string("cpe:/a:quicksilver_forums:quicksilver_forums:", vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    } else {
       register_host_detail(name:"App", value:string("cpe:/a:quicksilver_forums:quicksilver_forums"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    }  

    set_kb_item(name: string("www/", port, "/quicksilver"), value: string(vers," under ",install));

    info = string("\n\nQuicksilver Forums Version '");
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

