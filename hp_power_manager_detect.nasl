###############################################################################
# OpenVAS Vulnerability Test
# $Id: hp_power_manager_detect.nasl 8528 2018-01-25 07:57:36Z teissa $
#
# HP Power Manager Detection
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

tag_summary = "This host is running HP Power Manager, an UPS management and
monitoring utility.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100456");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 8528 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-25 08:57:36 +0100 (Thu, 25 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)");
 script_tag(name:"cvss_base", value:"0.0");

 script_name("HP Power Manager Detection");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_get_http_banner.nasl");
 script_require_ports("Services/www", 80);
 script_mandatory_keys("GoAhead-Webs/banner");

 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://h18000.www1.hp.com/products/servers/proliantstorage/power-protection/software/power-manager/index.html");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.100456";
SCRIPT_DESC = "HP Power Manager Detection";

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if("GoAhead-Webs" >!< banner)exit(0);

url = string("/CPage/About_English.asp");
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if( buf == NULL )continue;

if(egrep(pattern: "About HP Power Manager", string: buf, icase: TRUE))
{

    vers = string("unknown");
    ### try to get version 
    version = eregmatch(string: buf, pattern: "HP Power Manager ([0-9.]+)[ ]*([(Build 0-9)]*)",icase:TRUE);

    if(!isnull(version[1])) {
      
      if("Build" >< version[2]) {
        build = eregmatch(pattern: "\(Build ([0-9]+)\)", string: version[2]);
        vers = version[1] + "." + build[1];
      } else { 	
        vers=chomp(version[1]);
      }

     register_host_detail(name:"App", value:string("cpe:/a:hp:power_manager:", vers), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    
    } else {
       register_host_detail(name:"App", value:string("cpe:/a:hp:power_manager"), nvt:SCRIPT_OID, desc:SCRIPT_DESC);
    }  

    set_kb_item(name: string("www/", port, "/hp_power_manager"), value: string(vers));

    info = string("HP Power Manager Version '");
    info += string(vers);
    info += string("' was detected on the remote host.\n");

       if(report_verbosity > 0) {
         log_message(port:port,data:info);
       }
       exit(0);

 }

exit(0);

