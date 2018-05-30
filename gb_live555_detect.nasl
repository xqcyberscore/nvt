###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_live555_detect.nasl 10017 2018-05-30 07:17:29Z cfischer $
#
# LIVE555 Streaming Media Server Detection
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.107180");
  script_version("$Revision: 10017 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-30 09:17:29 +0200 (Wed, 30 May 2018) $");
  script_tag(name:"creation_date", value:"2017-05-22 12:42:40 +0200 (Mon, 22 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("LIVE555 Streaming Media Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("rtsp_detect.nasl");
  script_require_ports("Services/rtsp", 8554);

  script_tag(name:"summary", value:"Detection of the installed version of LIVE555 Streaming Media Server.

  The script detects the version of LIVE555 Streaming Media Server on the remote host via RSTP banner,
  to extract the version number and to set the KB entries.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

if (!port = get_kb_item("Services/rtsp"))
    port = 8554;
if (!banner = get_kb_item(string("RTSP/",port,"/Server")))
{
  exit( 0 );
}

if ("LIVE555 Streaming Media" >< banner ) {
    version = "unknown";
    Ver = eregmatch(pattern: "LIVE555 Streaming Media v([0-9.]+)", string: banner);
    if (!isnull(Ver[1])) {
        version = Ver[1];
        set_kb_item(name: "live555_streaming_media/ver", value: version);
    }
    set_kb_item( name:"live555_streaming_media/installed", value:TRUE );

    cpe = build_cpe(value:Ver, exp:"^([0-9.]+)", base:"cpe:/a:live555:streaming_media:");

    if(!cpe)
      cpe = 'cpe:/a:live5555:streaming_media';

    register_product( cpe:cpe, location:port + '/rtsp',port: port );
    log_message( data:build_detection_report( app:"LIVE555 Streaming Media",
                                          version:Ver[1],
                                          install:port + '/rtsp',
                                          cpe:cpe, concluded: Ver ),
                                          port:port);

    exit( 0 );

}

exit( 99 );
