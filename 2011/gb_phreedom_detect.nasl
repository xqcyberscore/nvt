###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phreedom_detect.nasl 3467 2016-06-09 20:02:36Z jan $
#
# Phreedom Detection
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

tag_summary = "This host is running Phreedom, an Enterprise Resource Planning System
made for small and medium sized business.";

if (description)
{
 
 script_id(103098);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 3467 $");
 script_tag(name:"last_modification", value:"$Date: 2016-06-09 22:02:36 +0200 (Thu, 09 Jun 2016) $");
 script_tag(name:"creation_date", value:"2011-03-01 13:10:12 +0100 (Tue, 01 Mar 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Phreedom Detection");

 script_tag(name:"qod_type", value:"remote_banner");
 script_summary("Checks for the presence of Phreedom");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.phreesoft.com");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);
if(!can_host_php(port:port))exit(0);

dirs = make_list("/phreedom",cgi_dirs());

foreach dir (dirs) {

 url = string(dir, "/index.php");
 req = http_get(item:url, port:port);
 buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
 if( buf == NULL )continue;

 if(egrep(pattern: "<title>Phreedom ERP</title>", string: buf, icase: TRUE))  {

     if(strlen(dir)>0) {
        install=dir;
     } else {
        install=string("/");
     }

    vers = string("unknown");

    set_kb_item(name: string("www/", port, "/Phreedom"), value: string(vers," under ",install));

    info = string("Phreedom Version '");
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

