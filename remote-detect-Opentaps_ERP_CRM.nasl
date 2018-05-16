###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-detect-Opentaps_ERP_CRM.nasl 9837 2018-05-15 09:54:15Z cfischer $
#
# Opentaps ERP + CRM Detection
#
# Author:
# Christian Eric Edjenguele <christian.edjenguele@owasp.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2 and later,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.101021");
  script_version("$Revision: 9837 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-15 11:54:15 +0200 (Tue, 15 May 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 00:18:39 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Opentaps ERP + CRM Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is running Opentaps ERP + CRM.

  Opentaps is a full-featured ERP + CRM suite which incorporates several open source projects,
  including Apache Geronimo, Tomcat, and OFBiz for the data model and transaction framework;
  Pentaho and JasperReports for business intelligence; Funambol for mobile device and Outlook integration;
  and the opentaps applications which provide user-driven applications for CRM, accounting and finance,
  warehouse and manufacturing, and purchasing and supply chain management.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:8080 );

# Nb: This seems to often redirect to a different port on the same system
verUrl = "/webtools/control/main";
verReq = http_get( item:verUrl, port:port );
verRes = http_keepalive_send_recv( port:port, data:verReq );
if( verRes =~ "^HTTP/1\.[01] 404" ) exit( 0 );

swRes = http_get_cache( item:"/", port:port );
if( ! swRes ) exit( 0 );

titlePattern = eregmatch( pattern:"<title>([a-zA-Z +]+)</title>", string:swRes, icase:TRUE );
if( ! titlePattern || 'opentaps' >!< titlePattern[0] ) exit( 0 );

set_kb_item( name:"OpentapsERP/installed", value:TRUE );
version = "unknown";
install = "/";

if( verRes ) {
  vers = eregmatch( pattern:'<p><a href="http://www.opentaps.org" class="tabletext">([a-zA-Z +]+)</a> ([0-9.]+).<br/>', string:verRes, icase:TRUE );
  if( vers[2] ) {
    version  = vers[2];
    conclUrl = report_vuln_url( port:port, url:verUrl, url_only:TRUE );
  }
}

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:opentaps:" );
if( isnull( cpe ) )
  cpe = 'cpe:/a:apache:opentaps';

register_product( cpe:cpe, location:install, port:port );

log_message( data:build_detection_report( app:"Opentaps ERP + CRM",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:vers[0],
                                          concludedUrl:conclUrl ),
                                          port:port );

exit( 0 );
