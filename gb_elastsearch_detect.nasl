###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elastsearch_detect.nasl 8613 2018-02-01 07:35:27Z cfischer $
#
# Elasticsearch Detection
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
  script_oid("1.3.6.1.4.1.25623.1.0.105031");
  script_version("$Revision: 8613 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-01 08:35:27 +0100 (Thu, 01 Feb 2018) $");
  script_tag(name:"creation_date", value:"2014-05-22 15:00:02 +0200 (Thu, 22 May 2014)");
  script_name("Elasticsearch Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 9200);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Check for the version of Elasticsearch.

  The script sends a connection request to the server and attempts to extract
  the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:9200 );
if( ! buf = http_get_cache( item:"/", port:port ) ) exit( 0 );

if( "application/json" >< buf && ( "build_hash" >< buf || "build_timestamp" >< buf ) &&
    "lucene_version" >< buf && ( "elasticsearch" >< buf || "You Know, for Search" >< buf ) ) {

  vers    = "unknown";
  cpe     = "cpe:/a:elasticsearch:elasticsearch";
  install = "/";

  version = eregmatch( string:buf, pattern:'number" : "([0-9a-z.]+)",', icase:TRUE );

  if( ! isnull( version[1] ) ) {
    vers = chomp( version[1] );
    cpe += ':' + vers;
  }

  url = "/_cat/indices?v";
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
  if( "health" >< buf || "status" >< buf || "index" >< buf ) {
    extra  = "Collected information (truncated) from " + report_vuln_url( port:port, url:url, url_only:TRUE ) + ' :\n\n';
    extra += substr( buf, 0, 1000 );
  }

  set_kb_item( name:"www/" + port + "/elasticsearch", value:vers );
  set_kb_item( name:"elasticsearch/installed", value:TRUE );

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Elasticsearch",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            extra:extra,
                                            concluded:version[0] ),
             				    port:port );
}

exit( 0 );
