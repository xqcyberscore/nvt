###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nessus_web_server_detect.nasl 5871 2017-04-05 13:33:48Z antu123 $
#
# Nessus Web Server Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801392");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 5871 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-05 15:33:48 +0200 (Wed, 05 Apr 2017) $");
  script_tag(name:"creation_date", value:"2010-08-04 08:26:41 +0200 (Wed, 04 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Nessus Web Server Version Detection");
  script_summary("Set the version of Nessus, Nessus Web Server/UI and the
  type of Nessus in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8834);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the running version of Nessus, Nessus Web Server/UI and the
  type of Nessus and saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:8834 );

## Construct https Request
sndReq = http_get( item:"/feed", port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

## Detection of Nessus 5.x and below
if( "<web_server_version>" >< rcvRes || "<server_version>" >< rcvRes || "<nessus_type>" >< rcvRes ) {

  nessusWsVersion = eregmatch( pattern:"<web_server_version>([0-9.]+)", string:rcvRes );
  nessusVersion = eregmatch( pattern:"<server_version>([0-9.]+)", string:rcvRes );
  nessusType = eregmatch( pattern:"<nessus_type>([a-zA-Z ()]+)", string:rcvRes );
  nessusFeed = eregmatch( pattern:"<feed>([a-zA-Z ]+)", string:rcvRes );
  nessusUiVersion = eregmatch( pattern:"<nessus_ui_version>([0-9.]+)", string:rcvRes );

  if( nessusVersion[1] ) {
    version = nessusVersion[1];
  } else {
    version = "Unknown";
  }

  if( nessusWsVersion[1] ) {
    versionWs = nessusWsVersion[1];
  } else {
    versionWs = "Unknown";
  }

  if( nessusType[1] ) {
    type = nessusType[1];
  } else {
    type = "Unknown";
  }

  if( nessusFeed[1] ) {
    feed = nessusFeed[1];
  } else {
    feed = "Unknown";
  }

  if( nessusUiVersion[1] ) {
    versionUi = nessusUiVersion[1];
  } else {
    versionUi = "Unknown";
  }

  set_kb_item( name:"www/" + port + "/Nessus/Web/Server", value:versionWs );
  set_kb_item( name:"www/" + port + "/nessus", value:version );
  set_kb_item( name:"nessus/installed", value:TRUE );

  ## Build CPE
  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tenable:nessus:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:tenable:nessus';

  ## Register Product and Build Report
  build_report(app: "Nessus",
               ver: version,
               cpe: cpe,
               insloc: port + '/tcp',
               concluded: nessusVersion[0] +
                      '\n' + nessusWsVersion[0] +
                      '\n' + nessusFeed[0] +
                      '\n' + nessusType[0],
               port: port,
               extra: 'Nessus Web Server version is: "' + versionWs + '"\n' +
                      'Nessus type is: "' + type + '"\n' +
                      'Nessus feed is: "' + feed + '"');

  set_kb_item( name:"www/" + port + "/nessus_web_ui", value:versionUi );

  ## Build CPE for Nessus Web UI
  cpe = build_cpe( value:versionUi, exp:"^([0-9.]+)", base:"cpe:/a:tenable:web_ui:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:tenable:web_ui';

  ## Register Product and Build Report
  build_report(app: "Nessus Web UI",
               ver: versionUi,
               cpe: cpe,
               insloc: port + '/tcp',
               concluded: nessusUiVersion[0],
               port: port,
               extra: '');

  exit(0);

}

## Detection of Nessus 6.x+
sndReq = http_get( item:"/server/properties", port:port );
rcvRes = http_keepalive_send_recv( port:port, data:sndReq, bodyonly:FALSE );

if( '"nessus_type":"' >< rcvRes || '"nessus_ui_version":"' >< rcvRes || '"nessus_ui_build":"' >< rcvRes ) {

    nessusVersion = eregmatch( pattern:'server_version":"([0-9.]+)"', string:rcvRes );
    nessusUiVersion = eregmatch( pattern:'nessus_ui_version":"([0-9.]+)"', string:rcvRes );
    nessusType = eregmatch( pattern:'nessus_type":"([a-zA-Z ()]+)"', string:rcvRes );

    if( nessusVersion[1] ) {
      version = nessusVersion[1];
    } else {
      version = "Unknown";
    }

    if( nessusUiVersion[1] ) {
      versionUi = nessusUiVersion[1];
    } else {
      versionUi = "Unknown";
    }

    if( nessusType[1] ) {
      type = nessusType[1];
    } else {
      type = "Unknown";
    }

    set_kb_item( name:"www/" + port + "/nessus", value:version );
    set_kb_item( name:"nessus/installed", value:TRUE );

    ## Build CPE for Nessus
    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:tenable:nessus:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:tenable:nessus';

    ## Register Product and Build Report
    build_report(app: "Nessus",
                 ver: version,
                 cpe: cpe,
                 insloc: port + '/tcp',
                 concluded: nessusVersion[0] +
                        '\n' +  nessusType[0],
                 port: port,
                 extra: 'Nessus type is: "' + type + '"');

    set_kb_item( name:"www/" + port + "/nessus_web_ui", value:versionUi );

    ## Build CPE for Nessus Web UI
    cpe = build_cpe( value:versionUi, exp:"^([0-9.]+)", base:"cpe:/a:tenable:web_ui:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:tenable:web_ui';

    ## Register Product and Build Report
    build_report(app: "Nessus Web UI",
                 ver: versionUi,
                 cpe: cpe,
                 insloc: port + '/tcp',
                 concluded: nessusUiVersion[0],
                 port: port,
                 extra: '');

    exit(0);
}

banner = get_http_banner( port:port );

if( concl = eregmatch( pattern:"Server: NessusWWW", string:banner, icase: TRUE) ) {

  version = "Unknown";
  cpe = 'cpe:/a:tenable:nessus';
  cpe2 = 'cpe:/a:tenable:web_ui';
  set_kb_item( name:"www/" + port + "/nessus", value:version );
  set_kb_item( name:"www/" + port + "/nessus_web_ui", value:version );
  set_kb_item( name:"nessus/installed", value:TRUE );

  ## Register Product and Build Report
  build_report(app: "Nessus",
               cpe: cpe,
               insloc: port + '/tcp',
               port: port,
               concluded: concl[0],
               extra: 'Unknown Nessus installation detected');

  ## Register Product and Build Report
  build_report(app: "Nessus Web UI",
               cpe: cpe2,
               insloc: port + '/tcp',
               port: port,
               concluded: concl[0],
               extra: 'Unknown Nessus Web UI installation detected');

}

exit(0);
