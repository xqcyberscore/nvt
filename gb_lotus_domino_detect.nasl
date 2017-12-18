###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lotus_domino_detect.nasl 8138 2017-12-15 11:42:07Z cfischer $
#
# Lotus/IBM Domino Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.100597");
  script_version("$Revision: 8138 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-15 12:42:07 +0100 (Fri, 15 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-04-22 20:18:17 +0200 (Thu, 22 Apr 2010)");
  script_name("Lotus/IBM Domino Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "smtpserver_detect.nasl", "webmirror.nasl");
  script_require_ports("Services/smtp", 25, 465, 587, "Services/pop3", 110,
                       "Services/imap", 143, "Services/www", 80);

  script_tag(name:"summary", value:"Detection of installed version of
  Lotus/IBM Domino.

  The script connects to SMTP (25), IMAP (143), POP3 (110) or HTTP (80) port,
  reads the banner and tries to get the Lotus/IBM Domino version from any
  of those.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("smtp_func.inc");
include("imap_func.inc");
include("pop3_func.inc");
include("global_settings.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

domino_ver = "unknown";
debug = 0;

ports = get_kb_list( "Services/smtp" );
if( ! ports ) ports = make_list( 25, 465, 587 );

foreach port( ports ) {

  if( get_port_state( port ) ) {

    banner = get_smtp_banner( port:port );

    ehlo = get_kb_item( "smtp/" + port + "/ehlo" );
    quit = get_kb_item( "smtp/" + port + "/quit" );
    noop = get_kb_item( "smtp/" + port + "/noop" );
    help = get_kb_item( "smtp/" + port + "/help" );
    rset = get_kb_item( "smtp/" + port + "/rset" );

    if( ( "Lotus Domino" >< banner || "IBM Domino" >< banner ) ||
        ( "pleased to meet you" >< ehlo && "Enter one of the following commands" >< help &&
          "Reset state" >< rset && "SMTP Service closing transmission channel" >< quit && "OK" >< noop ) ) {

      install    = port + "/tcp";
      domino_ver = "unknown";
      version    = eregmatch( pattern:"(Lotus|IBM) Domino Release ([0-9][^)]+)", string:banner );

      if( ! isnull( version[2] ) ) domino_ver = version[2];

      set_kb_item( name:"Domino/Version", value:domino_ver );
      set_kb_item( name:"Domino/Installed", value:TRUE );
      set_kb_item( name:"SMTP/domino", value:TRUE );
      set_kb_item( name:"SMTP/" + port + "/Domino", value:domino_ver );

      ## build cpe and store it as host_detail
      cpe = build_cpe( value:domino_ver, exp:"([0-9][^ ]+)", base:"cpe:/a:ibm:lotus_domino:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:ibm:lotus_domino";

      register_product( cpe:cpe, location:install, port:port, service:"smtp" );
      log_message( data:build_detection_report( app:"IBM/Lotus Domino",
                                                version:domino_ver,
                                                install:install,
                                                cpe:cpe,
                                                concluded:version[0] ),
                                                port:port );
    }
  }
}

ports = get_kb_list( "Services/imap" );
if( ! ports ) ports = make_list( 143 );

foreach port( ports ) {

  if( get_port_state( port ) ) {

    banner = get_imap_banner( port:port );

    if( banner && "Domino IMAP4 Server" >< banner ) {

      install    = port + "/tcp";
      domino_ver = "unknown";
      version    = eregmatch( pattern:"Domino IMAP4 Server Release ([0-9][^ ]+)", string:banner );

      if( ! isnull( version[1] ) ) domino_ver = version[1];

      set_kb_item( name:"Domino/Version", value:domino_ver );
      set_kb_item( name:"Domino/Installed", value:TRUE );

      ## build cpe and store it as host_detail
      cpe = build_cpe( value:domino_ver, exp:"([0-9][^ ]+)", base:"cpe:/a:ibm:lotus_domino:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:ibm:lotus_domino";

      register_product( cpe:cpe, location:install, port:port, service:"imap" );
      log_message( data:build_detection_report( app:"IBM/Lotus Domino",
                                                version:domino_ver,
                                                install:install,
                                                cpe:cpe,
                                                concluded:version[0] ),
                                                port:port );
    }
  }
}

ports = get_kb_list( "Services/pop3" );
if( ! ports ) ports = make_list( 110 );

foreach port( ports ) {

  if( get_port_state( port ) ) {

    banner = get_pop3_banner( port:port );

    if( banner && ( "Lotus Notes POP3 server" >< banner || "IBM Notes POP3 server" >< banner ) ) {

      install    = port + "/tcp";
      domino_ver = "unknown";
      version    = eregmatch( pattern:"(Lotus|IBM) Notes POP3 server version Release ([0-9][^ ]+)", string:banner );

      if( ! isnull( version[2] ) ) domino_ver = version[2];

      set_kb_item( name:"Domino/Version", value:domino_ver );
      set_kb_item( name:"Domino/Installed", value:TRUE );

      ## build cpe and store it as host_detail
      cpe = build_cpe( value:domino_ver, exp:"([0-9][^ ]+)", base:"cpe:/a:ibm:lotus_domino:" );
      if( isnull( cpe ) )
        cpe = "cpe:/a:ibm:lotus_domino";

      register_product( cpe:cpe, location:install, port:port, service:"pop3" );
      log_message( data:build_detection_report( app:"IBM/Lotus Domino",
                                                version:domino_ver,
                                                install:install,
                                                cpe:cpe,
                                                concluded:version[0] ),
                                                port:port );
    }
  }
}

if( get_kb_item( "Settings/disable_cgi_scanning" ) ) exit( 0 );

versionFiles = make_array( "/download/filesets/l_LOTUS_SCRIPT.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_LOTUS_SCRIPT.inf", "Version=([0-9.]+)",
                           "/download/filesets/l_SEARCH.inf", "Version=([0-9.]+)",
                           "/download/filesets/n_SEARCH.inf", "Version=([0-9.]+)",
                           "/iNotes/Forms5.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms6.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms7.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms8.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms85.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/iNotes/Forms9.nsf", "<!-- Domino Release ([0-9.]+)",
                           "/homepage.nsf", ">Domino Administrator ([0-9.]+) Help</" ); # Last fallback to get the major version

port = get_http_port( default:80 );

nsfList = get_kb_list( "www/" + port + "/content/extensions/nsf" );

cgis = "/domcfg.nsf";
final_ver = "unknown";

tmpCgis = make_list_unique( "/", cgi_dirs( port:port ) );
foreach tmpCgi( tmpCgis ) {
  if( tmpCgi == "/" ) tmpCgi = "";
  cgis = make_list( cgis, tmpCgi + "/domcfg.nsf" );
}

if( nsfList ) {
  nsfFiles = make_list_unique( nsfList, "/nonexistent.nsf", cgis );
} else {
  nsfFiles = make_list_unique( "/nonexistent.nsf", cgis );
}

foreach nsfFile( nsfFiles ) {

  banner = get_http_banner( port:port, file:nsfFile );

  req = http_get( item:nsfFile, port:port );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

  if( ( banner && ( "Lotus-Domino" >< banner || "Lotus Domino" >< banner ) ) ||
      ( 'src="/domcfg.nsf/' >< res && ( "self._domino_name" >< res || "Web Server Configuration" >< res ) ) ||
        'src="/webstart.nsf/IBMLogo.gif' >< res || "HTTP Web Server: IBM Notes Exception - File does not exist" >< res ) {

    concludedUrl = report_vuln_url( port:port, url:nsfFile, url_only:TRUE );
    domino_ver   = "unknown";
    installed    = TRUE;
    version = eregmatch( pattern:"Lotus-Domino/Release-([0-9.]+)", string:banner );
    inst = eregmatch( pattern:"(.*/)(.*\.nsf)", string:nsfFile );
    if( inst[1] ) {
      install = inst[1];
    } else {
      install = "/";
    }

    set_kb_item( name:"www/domino/" + port + "/dir", value:install );

    if( ! isnull( version[1] ) ) {
      domino_ver = version[1];
      concluded = version[0];
    } else {
      foreach file ( keys( versionFiles ) ) {

        dir = install;
        if( dir == "/" ) dir = "";
        url = dir + file;

        req = http_get( item:url, port:port );
        res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

        if( "Version=" >< res || "Domino Release" >< res || ">Domino Administrator" >< res ) {
          version = eregmatch( pattern:versionFiles[file], string:res );
          if( ! isnull(version[1] ) ) {
            if( domino_ver == "unknown" ) {
              domino_ver   = version[1];
              concluded    = version[0];
              concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
            }
            tmp_ver = version[1];
            if( debug ) display( "Current detected version in " + url + ": " + tmp_ver + ", previous version: " + domino_ver + '\n' );
            if( version_is_greater( version:tmp_ver, test_version:domino_ver ) ) {
              domino_ver   = tmp_ver;
              concluded    = version[0];
              concludedUrl = report_vuln_url( port:port, url:url, url_only:TRUE );
            }
          }
        }
      }
      if( concluded ) version[0] = concluded;
    }
    if( domino_ver != "unknown" ) final_ver = domino_ver;
  }
}

if( installed ) {

  install = port + "/tcp";

  set_kb_item( name:"Domino/Version", value:final_ver );
  set_kb_item( name:"dominowww/installed", value:TRUE );
  set_kb_item( name:"Domino/Installed", value:TRUE );

  ## build cpe and store it as host_detail
  cpe = build_cpe( value:final_ver, exp:"([0-9][^ ]+)", base:"cpe:/a:ibm:lotus_domino:" );
  if( isnull( cpe ) ) {
    cpe = build_cpe( value:final_ver, exp:"([0-9]+)", base:"cpe:/a:ibm:lotus_domino:" );
    if( isnull( cpe ) )
      cpe = "cpe:/a:ibm:lotus_domino";
  }

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"IBM/Lotus Domino",
                                            version:final_ver,
                                            install:install,
                                            cpe:cpe,
                                            concluded:version[0],
                                            concludedUrl:concludedUrl ),
                                            port:port );
}

exit( 0 );
