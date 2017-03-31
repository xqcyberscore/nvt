###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_performance_insight_detect.nasl 2836 2016-03-11 09:07:07Z benallard $
#
# HP Performance Insight Detection
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

tag_summary = "This host is running the HP OpenView Performance Insight Web
interface.";

if (description)
{
 
 script_id(103059);
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 2836 $");
 script_tag(name:"last_modification", value:"$Date: 2016-03-11 10:07:07 +0100 (Fri, 11 Mar 2016) $");
 script_tag(name:"creation_date", value:"2011-02-03 16:40:04 +0100 (Thu, 03 Feb 2011)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("HP Performance Insight Detection");

 script_summary("Checks for the presence of HP Performance Insight");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "https://h10078.www1.hp.com/cda/hpms/display/main/hpms_content.jsp?zn=bto&cp=1-11-15-119^1211_4000_100__");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.103059";
SCRIPT_DESC = "HP Performance Insight Detection";

port = get_http_port(default:8080);

if(!get_port_state(port))exit(0);

url = string("/");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )exit(0);

if("<h1>HP Performance Insight" >< buf || "HP OpenView Performance Insight Login" >< buf || "Hewlett-Packard" >< buf) 
{

    install ="/";
    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "<h4>Version ([^<]+)<",icase:TRUE);

    if ( !isnull(version[1]) ) {
       vers=chomp(version[1]);
    }

    set_kb_item(name: string("www/", port, "/hp_openview_insight"), value: string(vers," under ",install));
    if(vers == "unknown") {
      register_host_detail(name:"App", value:string("cpe:/a:hp:openview_performance_insight"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    } else {
      register_host_detail(name:"App", value:string("cpe:/a:hp:openview_performance_insight:",vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    }  

    info = string("HP OpenView Performance Insight Version '");
    info += string(vers);
    info += string("' was detected on the remote host in the following directory(s):\n\n");
    info += string(install, "\n");

       if(report_verbosity > 0) {
         log_message(port:port,data:info);
       }
       exit(0);

}

exit(0);

