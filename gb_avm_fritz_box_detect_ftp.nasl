###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avm_fritz_box_detect_ftp.nasl 8147 2017-12-15 13:51:17Z cfischer $
#
# AVM FRITZ!Box Detection (FTP)
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108039");
  script_version("$Revision: 8147 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 14:51:17 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-01-05 13:21:05 +0100 (Thu, 05 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("AVM FRITZ!Box Detection (FTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"summary", value:"The script attempts to identify an AVM FRITZ!Box via FTP
  banner and tries to extract the model and version number.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ftp_func.inc");

port = get_ftp_port( default:21 );
banner = get_ftp_banner( port:port );

if( "FRITZ!Box" >< banner && "FTP server ready." >< banner  ) {

  set_kb_item( name:"avm_fritz_box/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/ftp/detected", value:TRUE );
  set_kb_item( name:"avm_fritz_box/ftp/port", value:port );
  set_kb_item( name:"avm_fritz_box/ftp/" + port + "/concluded", value:banner );

  type = "unknown";
  model = "unknown";
  fw_version = "unknown";

  mo = eregmatch( pattern:'FRITZ!Box(FonWLAN|WLAN)?([0-9]+((v[0-9]+|vDSL|SL|LTE|Cable))?)', string:banner );
  if( ! isnull( mo[1] ) ) type = mo[1];
  # Adding spaces as the model in the FTP banner doesn't have any spaces
  # e.g. FRITZ!BoxFonWLAN7270v2 FTP server ready. / FRITZ!Box6490Cable(kdg) FTP server ready.
  if( ! isnull( mo[2] ) ) {
    mo[2] = ereg_replace( pattern:"(v[0-9]+|vDSL|SL|LTE|Cable)", string:mo[2], replace:" \1" );
    model = mo[2];
  }

  set_kb_item( name:"avm_fritz_box/ftp/" + port + "/type", value:type );
  set_kb_item( name:"avm_fritz_box/ftp/" + port + "/model", value:model );
  set_kb_item( name:"avm_fritz_box/ftp/" + port + "/firmware_version", value:fw_version );
}

exit( 0 );
