###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_detect.nasl 5888 2017-04-07 09:01:53Z teissa $
#
# Apache ActiveMQ Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105330");
 script_version ("$Revision: 5888 $");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_tag(name:"last_modification", value:"$Date: 2017-04-07 11:01:53 +0200 (Fri, 07 Apr 2017) $");
 script_tag(name:"creation_date", value:"2015-08-24 12:33:07 +0200 (Mon, 24 Aug 2015)");
 script_name("Apache ActiveMQ Detection");

 script_tag(name: "summary" , value: "The script sends a connection
 request to the server and attempts to detect Apache ActiveMQ.");

 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8161);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

mqport = get_http_port( default:8161 );

url = '/admin/index.jsp';
req = http_get(item:url, port:mqport);
buf = http_send_recv( port:mqport, data:req);
if(!buf) exit(0);

##Confirm Application
if(egrep(pattern:"(Apache )?ActiveMQ( Console)?</title>", string: buf, icase: TRUE) ||
    'WWW-Authenticate: basic realm="ActiveMQRealm"' >< buf)
{
  ##Getting version from admin page, in some cases admin page is accessible
  ## where we can get version
  version = eregmatch(pattern:'Version.*<td><b>([0-9.]+).*<td>ID', string:buf);
  if(version[1]){
    appVer = version[1];
  }
  else{
    appVer = "Unknown";
  }
  
  install = "/";
 
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:appVer, exp:"^([0-9.]+)", base:"cpe:/a:apache:activemq:");
  if(!cpe)
    cpe= "cpe:/a:apache:activemq";
   
  set_kb_item(name:"ActiveMQ/installed",value:TRUE);
  set_kb_item(name:"ActiveMQ/version", value:appVer);

  register_product( cpe:cpe, location:install, port:mqport);

  log_message( data: build_detection_report( app:"Apache ActiveMQ",
                                             install:install,
                                             version: appVer,
                                             concluded: appVer,
                                             cpe:cpe ),
                                             port:mqport);
  exit(0);
}
exit(0);
