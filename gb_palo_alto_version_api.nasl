###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_palo_alto_version_api.nasl 6032 2017-04-26 09:02:50Z teissa $
#
# Palo Alto PanOS Version Detection (XML-API)
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
 script_oid("1.3.6.1.4.1.25623.1.0.105262");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 6032 $");
 script_tag(name:"last_modification", value:"$Date: 2017-04-26 11:02:50 +0200 (Wed, 26 Apr 2017) $");
 script_tag(name:"creation_date", value:"2015-04-22 13:23:32 +0200 (Wed, 22 Apr 2015)");
 script_name("Palo Alto PanOS Version Detection (XML-API)");

 script_tag(name: "summary" , value: "This script performs XML-API based detection of the Palo Alto PanOS Version");

 script_tag(name:"qod_type", value:"package");

 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
 script_dependencies("gb_palo_alto_webgui_detect.nasl", "gather-package-list.nasl");
 script_mandatory_keys("palo_alto/webui");
 script_exclude_keys("panOS/system");

 script_add_preference(name:"API Username: ", value:"", type:"entry");
 script_add_preference(name:"API Password: ", type:"password", value:"");

 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

if( get_kb_item( "panOS/system" ) ) exit( 0 ); # already discovered by ssh

if( ! port = get_kb_item( "palo_alto/webui/port" ) ) exit( 0 );

user = script_get_preference( "API Username: " );
pass = script_get_preference( "API Password: " );

if( ! user || ! pass ) exit( 0 );

url = '/api/?type=keygen&user=' + user + '&password=' + pass;

req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "success" >!< buf || "<key>" >!< buf ) exit( 0 );

match = eregmatch( pattern:'<key>([^<]+)</key>', string:buf );
if( isnull( match[1] ) ) exit( 0 );

key = urlencode( str:match[1] );

url = '/api/?type=op&cmd=%3Cshow%3E%3Csystem%3E%3Cinfo%3E%3C%2Finfo%3E%3C%2Fsystem%3E%3C%2Fshow%3E&key=' + key;
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( "success" >!< buf || "<result>" >!< buf ) exit( 0 );

set_kb_item( name:"panOS/system", value: buf );
set_kb_item( name:"panOS/detected_by", value:"XML-API" );

exit( 0 );

