##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_detect.nasl 10709 2018-08-01 12:30:27Z cfischer $
#
# Apache Tomcat Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800371");
  script_version("$Revision: 10709 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-01 14:30:27 +0200 (Wed, 01 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-03-18 14:25:01 +0100 (Wed, 18 Mar 2009)");
  script_name("Apache Tomcat Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of Apache Tomcat.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

verPattern = "<strong>Tomcat ([0-9.]+)(-(RC|M)([0-9.]+))?"; # For /tomcat-docs/changelog.html.
verPattern2 = "Apache Tomcat( Version |\/)([0-9.]+)(-(RC|M)([0-9.]+))?"; # For other files

port = get_http_port( default:8080 );
host = http_host_name( dont_add_port:TRUE );

identified = FALSE;
verFound = FALSE;
conclUrl = "";
extraUrls = "";

foreach file( make_list( "/tomcat-docs/changelog.html", "/index.jsp", "/RELEASE-NOTES.txt", "/docs/RELEASE-NOTES.txt" ) ) {

  req = http_get( item:file, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( res =~ "^HTTP/1\.[0-1] 200" && "Apache Tomcat" >< res ) {
    identified = TRUE;
  }

  # The 404 error page is checked later. Continue here to avoid that we're matching against a wrong pattern
  if( res =~ "^HTTP/1\.[0-1] 404" ) continue;

  if( egrep( pattern:verPattern, string:res ) || egrep( pattern:verPattern2, string:res ) ) {
    conclUrl += report_vuln_url( port:port, url:file, url_only:TRUE ) + '\n';
    verFound = TRUE;
    break;
  }
}

if( ! verFound ) {

  foreach file( make_list( "/i_dont_exist", "/openvas/i_dont_exist" ) ) {

    req = http_get( item:file, port:port );
    res = http_keepalive_send_recv( port:port, data:req, fetch404:TRUE, bodyonly:FALSE );

    if( res =~ "^HTTP/1\.[0-1] 404" && "Apache Tomcat" >< res ) {
      identified = TRUE;
    }

    if( egrep( pattern:verPattern2, string:res ) ) {
      conclUrl += report_vuln_url( port:port, url:file, url_only:TRUE ) + '\n';
      verFound = TRUE;
      break;
    }
  }
}

authDirs = get_http_kb_auth_required( port:port, host:host );
if( authDirs ) {

  # Sort to not report changes on delta reports if just the order is different
  authDirs = sort( authDirs );

  foreach url( authDirs ) {

    if( "manager/" >!< url ) continue;

    authReq = http_get( item:url, port:port );
    authRes = http_keepalive_send_recv( port:port, data:authReq, bodyonly:FALSE );

    if( authRes =~ "^HTTP/1\.[01] 401" ) {
      if( "Tomcat Manager Application" >< authRes || "Tomcat Host Manager Application" >< authRes ||
          "Tomcat Manager Application" >< authRes ) {
        set_kb_item( name:"www/" + port + "/ApacheTomcat/auth_required", value:url );
        set_kb_item( name:"ApacheTomcat/auth_required", value:TRUE );
        identified = TRUE;
        extraUrls += report_vuln_url( port:port, url:url, url_only:TRUE ) + '\n';
      }
    }
  }
}

if( identified ) {

  vers = "unknown";
  install = "/";

  version = eregmatch( pattern:verPattern, string:res );

  if( "<strong>Tomcat" >< version[0] && ! isnull( version[1] ) ) {
    vers = version[1];
    if( version[2] ) {
      version[2] = ereg_replace( pattern:"-", string:version[2], replace: "." );
      vers = version[1] + version[2];
    }
  } else {

    version = eregmatch( pattern:verPattern2, string:res );

    if( "Apache Tomcat" >< version[0] && ! isnull( version[2] ) ) {
      vers = version[2];
      if( version[3] ) {
        version[3] = ereg_replace( pattern:"-", string:version[3], replace: "." );
        vers = version[2] + version[3];
      }
    }
  }

  set_kb_item( name:"www/" + port + "/ApacheTomcat", value:vers );
  set_kb_item( name:"ApacheTomcat/installed", value:TRUE );

  cpe = build_cpe( value:vers, exp:"^([0-9.RCM]+)", base:"cpe:/a:apache:tomcat:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/a:apache:tomcat';

  if( extraUrls ) {
    extra = 'Administrative Backends are available at the following location(s):\n' + extraUrls;
  }

  register_product( cpe:cpe, location:install, port:port );
  log_message( data:build_detection_report( app:"Apache Tomcat",
                                            version:vers,
                                            install:install,
                                            cpe:cpe,
                                            extra:extra,
                                            concluded:vers,
                                            concludedUrl:conclUrl ),
                                            port:port );
}

exit( 0 );