###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pfsense_detect.nasl 7754 2017-11-14 11:15:34Z asteins $
#
# pfSense Detection (Version)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112118");
  script_version("$Revision: 7754 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-14 12:15:34 +0100 (Tue, 14 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-13 08:56:05 +0100 (Mon, 13 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("pfSense Detection (Version)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_pfsense_remote_detect.nasl", "gb_pfsense_version.nasl", "gb_pfsense_snmp_detect.nasl");
  script_mandatory_keys("pfsense/installed");

  script_tag(name:"summary", value:"The script reports a detected pfSense including the
  version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if( ! get_kb_item( "pfsense/installed" ) ) exit( 0 );

detected_version = "unknown";

foreach source( make_list( "ssh", "http", "snmp" ) ) {

  version_list = get_kb_list( "pfsense/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      set_kb_item( name:"pfsense/version", value:version );
    }
  }
}

if( detected_version != "unknown" ) {
  cpe = "cpe:/a:pfsense:pfsense:" + version;
} else {
  cpe = "cpe:/a:pfsense:pfsense";
}

location = "/";
extra = '\nDetection methods:\n';

if( http_port = get_kb_list( "pfsense/http/port" ) ) {
  foreach port( http_port ) {
    concluded = get_kb_item( "pfsense/http/" + port + "/concluded" );
    concludedUrl = get_kb_item( "pfsense/http/" + port + "/concludedUrl" );
    extra += '\nHTTP(s) on port ' + port + '/tcp';
    if( concluded && concludedUrl ) {
      extra += '\nConcluded: ' + concluded + ' from URL: ' + concludedUrl + '\n';
    }
    register_product( cpe:cpe, location:location, port:port, service:"www" );
  }
}

if( ssh_port = get_kb_list( "pfsense/ssh/port" ) ) {
  foreach port( ssh_port ) {
    concluded = get_kb_item( "pfsense/ssh/" + port + "/concluded" );
    extra += '\nSSH on port ' + port + '/tcp\nConcluded: ' + concluded + '\n';
    register_product( cpe:cpe, location:location, port:port, service:"ssh" );
  }
}

if( snmp_port = get_kb_list( "pfsense/snmp/port" ) ) {
  foreach port( snmp_port ) {
    concluded = get_kb_item( "pfsense/snmp/" + port + "/concluded" );
    extra += '\nSNMP on port ' + port + '/udp\nConcluded from SNMP SysDesc: ' + concluded + '\n';
    register_product( cpe:cpe, location:location, port:port, service:"snmp", proto:"udp" );
  }
}

log_message( data:build_detection_report( app:"pfSense",
                                          version:detected_version,
                                          install:location,
                                          cpe:cpe,
                                          extra:extra ),
                                          port:0 );

exit( 0 );
