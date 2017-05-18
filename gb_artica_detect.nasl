###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_artica_detect.nasl 5877 2017-04-06 09:01:48Z teissa $
#
# Artica Detection
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100870");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 5877 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-06 11:01:48 +0200 (Thu, 06 Apr 2017) $");
 script_tag(name:"creation_date", value:"2010-10-26 13:33:58 +0200 (Tue, 26 Oct 2010)");
 script_tag(name:"cvss_base", value:"0.0");
 script_name("Artica Detection");
 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 9000);
 script_exclude_keys("Settings/disable_cgi_scanning");

 script_tag(name : "summary" , value : "This host is running Artica, a full web based management console.");

 script_xref(name : "URL" , value : "http://www.artica.fr/");

 script_tag(name:"qod_type", value:"remote_banner");


 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");
include("host_details.inc");

port = get_http_port( default:9000 );

req = http_get( item:"/logon.php", port:port );
buf = http_keepalive_send_recv( port:port, data:req );
if( buf == NULL ) exit( 0 );

if( "lighttpd" >< buf && "artica-language" >< buf && "artica-template" >< buf && "Artica for postfix" >< buf ) {

   set_kb_item( name: "www/" + port + "/artica", value: TRUE );

   ## CPE is currently not registered
   cpe = 'cpe:/a:artica:artica';

   ## Register Product and Build Report
   register_product( cpe:cpe, location:port + '/tcp', port:port );

   log_message( data: build_detection_report( app:"Artica",
                                                  install:port + '/tcp',
                                                  cpe:cpe),
                                                  port:port);
}

exit( 0 );
