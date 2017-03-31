###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_detect.nasl 4966 2017-01-06 15:21:01Z cfi $
#
# AVM FRITZ!Box Detection (Version)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103910");
  script_version("$Revision: 4966 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-06 16:21:01 +0100 (Fri, 06 Jan 2017) $");
  script_tag(name:"creation_date", value:"2014-02-19 13:21:05 +0100 (Wed, 19 Feb 2014)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AVM FRITZ!Box Detection (Version)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_avm_fritz_box_detect_http.nasl", "gb_avm_fritz_box_detect_sip.nasl",
                      "gb_avm_fritz_box_detect_upnp.nasl", "gb_avm_fritz_box_detect_ftp.nasl");
  script_mandatory_keys("avm_fritz_box/detected");

  script_tag(name:"summary", value:"The script reports a detected AVM FRITZ!Box including the model,
  version number and exposed services.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

detected_type = "unknown";
detected_model = "unknown";
detected_firmware = "unknown";

foreach source( make_list( "sip/tcp", "sip/udp", "upnp", "ftp", "http" ) ) {

  type_list = get_kb_list( "avm_fritz_box/" + source + "/*/type" );
  foreach type( type_list ) {
    if( type != "unknown" && detected_type == "unknown" ) {
      detected_type = type;
      set_kb_item( name:"avm/fritz/type", value:type );
    }
  }

  model_list = get_kb_list( "avm_fritz_box/" + source + "/*/model" );
  foreach model( model_list ) {
    if( model != "unknown" && detected_model == "unknown" ) {
      detected_model = model;
      set_kb_item( name:"avm/fritz/model", value:model );
    }
  }

  firmware_list = get_kb_list( "avm_fritz_box/" + source + "/*/firmware_version" );
  foreach firmware( firmware_list ) {
    if( firmware != "unknown" && detected_firmware == "unknown" ) {
      detected_firmware = firmware;
      set_kb_item( name:"avm/fritz/firmware_version", value:firmware );
    }
  }
}

if( detected_model != "unknown" ) {
  cpe_model = str_replace( string:tolower( detected_model ), find:" ", replace:"_" );
  cpe = build_cpe( value:detected_firmware, exp:"^([0-9.]+)", base:"cpe:/a:avm:fritzbox:" + cpe_model + ":" );
} else {
  cpe = build_cpe( value:detected_firmware, exp:"^([0-9.]+)", base:"cpe:/a:avm:fritzbox::" );
}

if( isnull( cpe ) ) {
  if( detected_model != "unknown" ) {
    cpe = "cpe:/a:avm:fritzbox:" + cpe_model;
  } else {
    cpe = "cpe:/a:avm:fritzbox";
  }
}

app = "AVM FRITZ!Box";
if( detected_type != "unknown" ) {
  app += " " + detected_type;
}
if( detected_model != "unknown" ) {
  app += " " + detected_model;
}

location = "/";
extra = '\nExposed services:\n';

if( http_port = get_kb_list( "avm_fritz_box/http/port" ) ) {
  foreach port( http_port ) {
    extra += "HTTP(s) on port " + port + '/tcp\n';
    register_product( cpe:cpe, location:location, port:port, service: "www" );
  }
}

if( sip_port = get_kb_list( "avm_fritz_box/sip/tcp/port" ) ) {
  foreach port( sip_port ) {
    concluded = get_kb_item( "avm_fritz_box/sip/tcp/" + port + "/concluded" );
    extra += "SIP on port " + port + '/tcp\nBanner: ' + concluded + '\n';
    register_product( cpe:cpe, location:location, port:port, service:"sip" );
  }
}

if( sip_port = get_kb_list( "avm_fritz_box/sip/udp/port" ) ) {
  foreach port( sip_port ) {
    concluded = get_kb_item( "avm_fritz_box/sip/udp/" + port + "/concluded" );
    extra += "SIP on port " + port + '/udp\nBanner: ' + concluded + '\n';
    register_product( cpe:cpe, location:location, port:port, service:"sip", proto:"udp" );
  }
}

if( upnp_port = get_kb_list( "avm_fritz_box/upnp/port" ) ) {
  foreach port( upnp_port ) {
    concluded = get_kb_item( "avm_fritz_box/upnp/" + port + "/concluded" );
    extra += "UPnP on port " + port + '/udp\nBanner: ' + concluded + '\n';
    register_product( cpe:cpe, location:location, port:port, service:"upnp", proto:"udp" );
  }
}

if( ftp_port = get_kb_list( "avm_fritz_box/ftp/port" ) ) {
  foreach port( ftp_port ) {
    concluded = get_kb_item( "avm_fritz_box/ftp/" + port + "/concluded" );
    extra += "FTP on port " + port + '/ftp\nBanner: ' + concluded + '\n';
    register_product( cpe:cpe, location:location, port:port, service: "ftp" );
  }
}

log_message( data:build_detection_report( app:app,
                                          version:detected_firmware,
                                          install:location,
                                          cpe:cpe,
                                          extra:extra ),
                                          port:0 );

exit( 0 );
