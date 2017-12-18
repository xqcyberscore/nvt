###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-detect-Opentaps_ERP_CRM.nasl 8140 2017-12-15 12:08:32Z cfischer $
#
# This script ensure that the Opentaps ERP + CRM is installed and running
#
# remote-detect-Opentaps_ERP_CRM.nasl
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
  script_version("$Revision: 8140 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 13:08:32 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2009-04-23 00:18:39 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Opentaps ERP + CRM service detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Service detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The remote host is running Opentaps ERP + CRM.

  Opentaps is a full-featured ERP + CRM suite which incorporates several open source projects,
  including Apache Geronimo, Tomcat, and OFBiz for the data model and transaction framework;
  Pentaho and JasperReports for business intelligence; Funambol for mobile device and Outlook integration;
  and the opentaps applications which provide user-driven applications for CRM, accounting and finance,
  warehouse and manufacturing, and purchasing and supply chain mmanagement.";

  tag_solution = "It's recommended to allow connection to this host only from trusted hosts or networks,
  or disable the service if not used.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:8080 );

report = '';

versionRequest = http_get( item:"/webtools/control/main", port:port );
versionReply   = http_keepalive_send_recv( port:port, data:versionRequest );

softwareReply = http_get_cache( item:"/", port:port );

if( versionReply =~ "^HTTP/1\.[01] 404" ) exit( 0 );

if( softwareReply ) {

  servletContainer = eregmatch( pattern:"Server: Apache-Coyote/([0-9.]+)", string:softwareReply, icase:TRUE );
  opentapsTitlePattern = eregmatch( pattern:"<title>([a-zA-Z +]+)</title>", string:softwareReply, icase:TRUE );

  if( opentapsTitlePattern ) {
    if( 'opentaps' >< opentapsTitlePattern[0] ) {
      report += " The remote host is running " + opentapsTitlePattern[1];
      set_kb_item( name:"OpentapsERP/installed", value:TRUE );
      replace_kb_item( name:"OpentapsERP/port", value:port );
    } else {
      exit( 0 );
    }
  } else {
    exit( 0 );
  }

  if( servletContainer ) {
    set_kb_item( name:"ApacheCoyote/installed", value:TRUE );
    replace_kb_item( name:"ApacheCoyote/version", value:servletContainer[1] );
    report += " on " + servletContainer[0];
  }
}

if( versionReply ) {

  version = eregmatch( pattern:'<p><a href="http://www.opentaps.org" class="tabletext">([a-zA-Z +]+)</a> ([0-9.]+).<br/>', string:versionReply, icase:TRUE );
  servletContainer = eregmatch( pattern:"Server: Apache-Coyote/([0-9.]+)", string:versionReply, icase:TRUE );

  if( version ) {
    report += " Detected " + version[1] + " " + version[2];
    set_kb_item( name:"OpentapsERP/installed", value:TRUE );
    replace_kb_item( name:"OpentapsERP/version", value:version[2] );
    replace_kb_item( name:"OpentapsERP/port", value:port );
  } else {
    exit( 0 );
  }

  if( servletContainer ) {
    set_kb_item( name:"ApacheCoyote/installed", value:TRUE );
    replace_kb_item( name:"ApacheCoyote/version", value:servletContainer[1] );
    report += " on " + servletContainer[0];
  }
}

if( strlen( report ) > 0 ) {
  log_message( port:port, data:report );
}

exit( 0 );
