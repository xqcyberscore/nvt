###############################################################################
# OpenVAS Vulnerability Test
# $Id: remote-detect-ApacheOfbiz.nasl 9822 2018-05-14 13:18:48Z cfischer $
#
# Apache Open For Business (OFBiz) Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.101019");
  script_version("$Revision: 9822 $");
  script_tag(name:"last_modification", value:"$Date: 2018-05-14 15:18:48 +0200 (Mon, 14 May 2018) $");
  script_tag(name:"creation_date", value:"2009-04-18 23:46:40 +0200 (Sat, 18 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Apache Open For Business (OFBiz) Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Christian Eric Edjenguele <christian.edjenguele@owasp.org>");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is running the Apache OFBiz.

  Apache OFBiz is an Apache Top Level Project. As automation software it comprises a mature suite of enterprise
  applications that integrate and automate many of the business processes of an enterprise.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:8443 );

foreach module( make_list( '/accounting/control/main', '/partymgr/control/main', '/webtools/control/main', '/ordermgr/control/main' ) ) {

  req = http_get( item:module, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( ! res || res !~ "^HTTP/1\.[01] 200" ) continue;

  # Version 16: <title>OFBiz&#x3a; Accounting Manager: Login</title>
  # Older version seems to use : instead of &#x3a;
  # <title>OFBiz: Accounting Manager: Login</title>
  ofbizTitle = eregmatch( pattern:"<title>([a-zA-Z: &#3;]+)</title>", string:res, icase:TRUE );
  if( ( ofbizTitle && 'ofbiz' >< tolower( ofbizTitle[1] ) ) || "neogia_logo.png" >< res ) {
    report += '\nDetected Apache Open For Business Module[' + ofbizTitle[1] +']';
    set_kb_item( name:"ApacheOFBiz/installed", value:TRUE );
    installed = TRUE;

    vendor = eregmatch( pattern:'powered by <a href="http://ofbiz.apache.org" target="_blank">([a-zA-Z ]+) ([0-9.]+)', string:res, icase:TRUE );
    if( vendor ) {
      version = vendor[2];
      report += "\nDetected " + vendor[1] + " " + version;
      replace_kb_item( name:"ApacheOFBiz/" + port + "/version", value:version );
    }
  }
}

if( installed ) {

  if( ! version ) version = "unknown";
  install = "/";

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:apache:open_for_business_project:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:apache:open_for_business_project';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Apache Open For Business (OFBiz)",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:vendor[0],
                                            extra:report ),
                                            port:port );
}

exit( 0 );
