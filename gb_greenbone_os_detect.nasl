###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenbone_os_detect.nasl 8078 2017-12-11 14:28:55Z cfischer $
#
# Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (Version)
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103220");
  script_version("$Revision: 8078 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-11 15:28:55 +0100 (Mon, 11 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-08-23 15:25:10 +0200 (Tue, 23 Aug 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection (Version)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_greenbone_os_detect_http.nasl", "gb_greenbone_os_detect_snmp.nasl", "gb_greenbone_os_detect_ssh.nasl");
  script_mandatory_keys("greenbone/gos/detected");

  script_tag(name:"summary", value:"Detection of Greenbone Security Manager (GSM)
  and Greenbone OS (GOS) including version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! get_kb_item( "greenbone/gos/detected" ) ) exit( 0 );

detected_version = "unknown";

foreach source( make_list( "ssh", "http", "snmp" ) ) {

  version_list = get_kb_list( "greenbone/gos/" + source + "/*/version" );
  foreach version( version_list ) {
    if( version != "unknown" && detected_version == "unknown" ) {
      detected_version = version;
      set_kb_item( name:"greenbone/gos/version", value:version );
    }
  }
}

if( detected_version != "unknown" ) {
  cpe = "cpe:/o:greenbone:greenbone_os:" + version;
} else {
  cpe = "cpe:/o:greenbone:greenbone_os";
}

location = "/";
extra = '\nDetection methods:\n';

if( http_port = get_kb_list( "greenbone/gos/http/port" ) ) {
  foreach port( http_port ) {
    concluded = get_kb_item( "greenbone/gos/http/" + port + "/concluded" );
    concludedUrl = get_kb_item( "greenbone/gos/http/" + port + "/concludedUrl" );
    extra += '\nHTTP(s) on port ' + port + '/tcp';
    if( concluded && concludedUrl ) {
      extra += '\nConcluded: ' + concluded + ' from URL: ' + concludedUrl + '\n';
    }
    register_product( cpe:cpe, location:location, port:port, service:"www" );
  }
}

if( ssh_port = get_kb_list( "greenbone/gos/ssh/port" ) ) {
  foreach port( ssh_port ) {
    concluded = get_kb_item( "greenbone/gos/ssh/" + port + "/concluded" );
    extra += '\nSSH on port ' + port + '/tcp';
    if( concluded ) {
      extra += '\nConcluded: ' + concluded + '\n';
    }
    register_product( cpe:cpe, location:location, port:port, service:"ssh" );
  }
}

if( snmp_port = get_kb_list( "greenbone/gos/snmp/port" ) ) {
  foreach port( snmp_port ) {
    concluded    = get_kb_item( "greenbone/gos/snmp/" + port + "/concluded" );
    concludedOID = get_kb_item( "greenbone/gos/snmp/" + port + "/concludedOID" );
    extra += '\nSNMP on port ' + port + '/udp';
    if( concluded && concludedOID ) {
      extra += '\nConcluded from ' + concluded + ' via OID: ' + concludedOID + '\n';
    } else if( concluded ) {
      extra += '\nConcluded from SNMP SysDesc: ' + concluded + '\n';
    }
    register_product( cpe:cpe, location:location, port:port, service:"snmp", proto:"udp" );

    if( gsm_type = get_kb_item( "greenbone/gsm/snmp/" + port + "/type" ) ) {
      register_product( cpe:"cpe:/h:greenbone:gsm_" + gsm_type, location:location, port:port, service:"snmp", proto:"udp" );
    }
  }
}

log_message( data:build_detection_report( app:"Greenbone OS",
                                          version:detected_version,
                                          install:location,
                                          cpe:cpe,
                                          extra:extra ),
                                          port:0 );

exit( 0 );
