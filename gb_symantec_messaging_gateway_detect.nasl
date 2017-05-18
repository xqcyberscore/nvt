###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_detect.nasl 5877 2017-04-06 09:01:48Z teissa $
#
# Symantec Messaging Gateway Version Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
 script_oid("1.3.6.1.4.1.25623.1.0.103612");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 5877 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-06 11:01:48 +0200 (Thu, 06 Apr 2017) $");
 script_tag(name:"creation_date", value:"2016-05-17 13:22:07 +0200 (Tue, 17 May 2016)");
 script_name("Symantec Messaging Gateway Version Detection");

 script_tag(name: "summary" , value: "This Script reports the detected Symantec Messaging Gateway Version");

 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_family("Product detection");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_symantec_messaging_gateway_http_detect.nasl","gb_symantec_messaging_gateway_ssh_detect.nasl","gb_symantec_messaging_gateway_snmp_detect.nasl");
 script_mandatory_keys("smg/installed");
 exit(0);
}

include("host_details.inc");

source = "ssh";

if( ! version = get_kb_item( "symantec_messaging_gateway/version/" + source ) ) source = "snmp";

if( ! version )
  if( ! version = get_kb_item( "symantec_messaging_gateway/version/" + source ) ) source = "http";

if( ! version )
  if( ! version = get_kb_item( "symantec_messaging_gateway/version/" + source ) ) exit( 0 );

set_kb_item( name:"/Symantec/Messaging/Gateway/installed", value:TRUE );
cpe = "cpe:/a:symantec:messaging_gateway";

if( version != "unknown" )
{
  set_kb_item( name:"smg/version", value:version );
  cpe += ':' + version;
}

if( patch = get_kb_item( "symantec_messaging_gateway/patch/" + source ) )
  set_kb_item( name:"smg/patch", value:patch );

register_product(cpe:cpe, location:source );

report = 'Detected Symantec Messaging Gateway\n' + 
         'Version: ' + version + '\n';

if( patch ) report += 'Patch:   ' + patch + '\n';
report += 'Detection Source: ' + source + '\n';

log_message(port:0, data:report );

exit( 0 );

