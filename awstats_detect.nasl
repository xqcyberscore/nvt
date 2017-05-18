###############################################################################
# OpenVAS Vulnerability Test
# $Id: awstats_detect.nasl 5720 2017-03-24 14:15:57Z cfi $
#
# AWStats Detection
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

tag_summary = "This host is running AWStats, a free powerful and featureful tool that
generates advanced web, streaming, ftp or mail server statistics,
graphically.";

if (description)
{
 script_id(100376);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5720 $");
 script_tag(name:"last_modification", value:"$Date: 2017-03-24 15:15:57 +0100 (Fri, 24 Mar 2017) $");
 script_tag(name:"creation_date", value:"2009-12-03 12:57:42 +0100 (Thu, 03 Dec 2009)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("AWStats Detection");
 script_category(ACT_GATHER_INFO);
 script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://awstats.sourceforge.net/");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100376";
SCRIPT_DESC = "AWStats Detection";

port = get_http_port(default:80);
foreach dir( make_list_unique( "/awstats", "/stats", "/logs", "/awstats/cgi-bin", "/statistics", "/statistik/cgi-bin", "/awstats-cgi", cgi_dirs( port:port ) ) ) {

 install = dir;
 if( dir == "/" ) dir = "";
 url = string(dir, "/awstats.pl?framename=mainright");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: 'content="Awstats - Advanced Web Statistics', string: buf, icase: TRUE) ||
    egrep(pattern: "AWStats UseFramesWhenCGI", string: buf)                                ||
    egrep(pattern: "Created by awstats", string: buf)                                      ||
    egrep(pattern: "CreateDirDataIfNotExists", string: buf))  {

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "Advanced Web Statistics ([0-9.]+)",icase:TRUE);

    if ( !isnull(version[1]) ) {
      vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/awstats"), value: string(vers," under ",install));
    if("unknown" >!< vers) {
      register_host_detail(name:"App", value:string("cpe:/a:awstats:awstats:",vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    } else {
      register_host_detail(name:"App", value:string("cpe:/a:awstats:awstats"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    }  

    info = string("\n\nAwstats Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

    log_message(port:port,data:info);
    exit(0);
  }
}

exit(0);
