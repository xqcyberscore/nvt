###############################################################################
# OpenVAS Vulnerability Test
#
# ManageEngine ServiceDesk Plus Detection (HTTP)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140780");
  script_version("2019-08-23T04:24:16+0000");
  script_tag(name:"last_modification", value:"2019-08-23 04:24:16 +0000 (Fri, 23 Aug 2019)");
  script_tag(name:"creation_date", value:"2018-02-16 10:29:54 +0700 (Fri, 16 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ManageEngine ServiceDesk Plus Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of ManageEngine ServiceDesk Plus.

  The script sends a connection request to the server and attempts to detect ManageEngine ServiceDesk Plus and to
  extract its version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );

res = http_get_cache( port:port, item:"/" );

if( "<title>ManageEngine ServiceDesk Plus</title>" >< res && "j_security_check" >< res ) {

  location  = "/";
  concluded = '    URL:     ' + report_vuln_url( port:port, url:location, url_only:TRUE );

  # title='ManageEngine ServiceDesk Plus'>ManageEngine ServiceDesk Plus</a><span>&nbsp;&nbsp;|&nbsp;&nbsp;8.0.0</span></b></td></tr>
  version = eregmatch( string:res, pattern:"ManageEngine ServiceDesk Plus</a><span>&nbsp;&nbsp;\|&nbsp;&nbsp;([0-9.]+)", icase:TRUE);
  if( isnull( version[1] ) ) {
    # example: getCustomHtml('/custom/login/log-logo.png','ManageEngine ServiceDesk Plus','http://www.manageengine.com/products/service-desk/index.html','10.0',''); //NO OUTPUTENCODING
    # or: getCustomHtml('/custom/customimages/Custom_LoginLogo.gif','ManageEngine ServiceDesk Plus','http://www.manageengine.com/products/service-desk/index.html','9.3'); //NO OUTPUTENCODING
    version = eregmatch( string:res, pattern:"ManageEngine ServiceDesk Plus','http(s)?://.*','([0-9.]+)'", icase:TRUE );
  }

  if( ! isnull( version[2] ) ) {
    major = version[2];
    concluded += '\n    Version: ' + version[0];
    set_kb_item( name:"manageengine/servicedesk_plus/http/" + port + "/version", value:major );
  }

  # e.g.:
  # loginstyle.css?9328
  # Login.js?9328
  # /scripts/Login.js?8022
  # /style/select2.css?9425
  buildnumber = eregmatch( pattern:"\.(css|js)\?([0-9]+)", string:res);
  if( ! isnull( buildnumber[2] ) ) {
    build = buildnumber[2];
    appVer = major + 'b' + build;
    concluded += '\n    Build:   ' + buildnumber[0];
    set_kb_item( name:"manageengine/servicedesk_plus/http/" + port + "/build", value:build );
  }

  set_kb_item( name:"manageengine/servicedesk_plus/detected", value:TRUE );
  set_kb_item( name:"manageengine/servicedesk_plus/http/" + port + "/detected", value:TRUE );
  set_kb_item( name:"manageengine/servicedesk_plus/http/" + port + "/location", value:location );
  set_kb_item( name:"manageengine/servicedesk_plus/http/port", value:port );
  set_kb_item( name:"manageengine/servicedesk_plus/http/" + port + "/concluded", value:concluded );
}

exit( 0 );
