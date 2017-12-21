###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nessus_web_server_detect.nasl 8206 2017-12-21 07:17:57Z cfischer $
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
  script_version("$Revision: 8206 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:17:57 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-08-04 08:26:41 +0200 (Wed, 04 Aug 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Nessus Web Server Version Detection");
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

## Detection of Nessus 5.x and below
url = "/feed";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "<web_server_version>" >< res || "<server_version>" >< res || "<nessus_type>" >< res ) {

  conclUrl  = report_vuln_url( port:port, url:url, url_only:TRUE );
  install   = port + "/tcp";
  version   = "unknown";
  versionWs = "unknown";
  type      = "unknown";
  feed      = "unknown";
  versionUi = "unknown";

  nessusWsVersion = eregmatch( pattern:"<web_server_version>([0-9.]+)", string:res );
  nessusVersion   = eregmatch( pattern:"<server_version>([0-9.]+)", string:res );
  nessusType      = eregmatch( pattern:"<nessus_type>([a-zA-Z ()]+)", string:res );
  nessusFeed      = eregmatch( pattern:"<feed>([a-zA-Z ]+)", string:res );
  nessusUiVersion = eregmatch( pattern:"<nessus_ui_version>([0-9.]+)", string:res );

  if( nessusVersion[1] )   version = nessusVersion[1];
  if( nessusWsVersion[1] ) versionWs = nessusWsVersion[1];
  if( nessusType[1] )      type = nessusType[1];
  if( nessusFeed[1] )      feed = nessusFeed[1];
  if( nessusUiVersion[1] ) versionUi = nessusUiVersion[1];

  set_kb_item( name:"nessus/installed", value:TRUE );
  set_kb_item( name:"www/" + port + "/Nessus/Web/Server", value:versionWs );
  set_kb_item( name:"www/" + port + "/nessus", value:version );
  set_kb_item( name:"www/" + port + "/nessus_web_ui", value:versionUi );

  register_and_report_cpe( app:"Nessus", ver:version, concluded:nessusVersion[0] + '\n' + nessusWsVersion[0] + '\n' + nessusFeed[0] + '\n' + nessusType[0],
                           base:"cpe:/a:tenable:nessus:", expr:"^([0-9.]+)", insloc:install, regPort:port, conclUrl:conclUrl,
                           extra:'Nessus Web Server version is: "' + versionWs + '"\n' + 'Nessus type is: "' + type + '"\n' + 'Nessus feed is: "' + feed + '"' );

  register_and_report_cpe( app:"Nessus Web UI", ver:versionUi, concluded:nessusUiVersion[0], base:"cpe:/a:tenable:web_ui:", expr:"^([0-9.]+)", insloc:install, regPort:port, conclUrl:conclUrl );

  exit( 0 );
}

## Detection of Nessus 6.x+
url = "/server/properties";
req = http_get( item:url, port:port );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( '"nessus_type":"' >< res || '"nessus_ui_version":"' >< res || '"nessus_ui_build":"' >< res ) {

  conclUrl  = report_vuln_url( port:port, url:url, url_only:TRUE );
  install   = port + "/tcp";
  version   = "unknown";
  versionUi = "unknown";
  type      = "unknown";

  nessusVersion   = eregmatch( pattern:'server_version":"([0-9.]+)"', string:res );
  nessusUiVersion = eregmatch( pattern:'nessus_ui_version":"([0-9.]+)"', string:res );
  nessusType      = eregmatch( pattern:'nessus_type":"([a-zA-Z ()]+)"', string:res );

  if( nessusVersion[1] )   version = nessusVersion[1];
  if( nessusUiVersion[1] ) versionUi = nessusUiVersion[1];
  if( nessusType[1] )      type = nessusType[1];

  set_kb_item( name:"nessus/installed", value:TRUE );
  set_kb_item( name:"www/" + port + "/nessus", value:version );
  set_kb_item( name:"www/" + port + "/nessus_web_ui", value:versionUi );

  register_and_report_cpe( app:"Nessus", ver:version, concluded:nessusVersion[0] + '\n' +  nessusType[0], base:"cpe:/a:tenable:nessus:", expr:"^([0-9.]+)",
                           insloc:install, regPort:port, conclUrl:conclUrl, extra:'Nessus type is: "' + type + '"' );

  register_and_report_cpe( app:"Nessus Web UI", ver:versionUi, concluded:nessusUiVersion[0], base:"cpe:/a:tenable:web_ui:", expr:"^([0-9.]+)",
                           insloc:install, regPort:port, conclUrl:conclUrl );

  exit( 0 );
}

banner = get_http_banner( port:port );

if( concl = eregmatch( pattern:"Server: NessusWWW", string:banner, icase:TRUE) ) {

  version = "unknown";
  install = port + "/tcp";

  cpe  = "cpe:/a:tenable:nessus";
  cpe2 = "cpe:/a:tenable:web_ui";

  set_kb_item( name:"nessus/installed", value:TRUE );
  set_kb_item( name:"www/" + port + "/nessus", value:version );
  set_kb_item( name:"www/" + port + "/nessus_web_ui", value:version );

  register_and_report_cpe( app:"Nessus", ver:version, concluded:concl[0], cpename:cpe, insloc:install, regPort:port, extra:"Unknown Nessus installation detected" );
  register_and_report_cpe( app:"Nessus Web UI", ver:version, concluded:concl[0], cpename:cpe2, insloc:install, regPort:port, extra:"Unknown Nessus Web UI installation detected" );
}

exit( 0 );
