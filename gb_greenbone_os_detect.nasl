###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_greenbone_os_detect.nasl 6781 2017-07-21 08:31:34Z cfischer $
#
# Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103220");
  script_version("$Revision: 6781 $");
  script_tag(name:"last_modification", value:"$Date: 2017-07-21 10:31:34 +0200 (Fri, 21 Jul 2017) $");
  script_tag(name:"creation_date", value:"2011-08-23 15:25:10 +0200 (Tue, 23 Aug 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "gather-package-list.nasl");
  script_require_ports("Services/www", 80, 443, "Services/ssh", 22);

  script_tag(name:"summary", value:"Detection of Greenbone Security Manager (GSM)
  and Greenbone OS (GOS).

  The script sends a connection request via HTTP and SSH to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");
include("ssh_func.inc");

SCRIPT_DESC = "Greenbone Security Manager (GSM) / Greenbone OS (GOS) Detection";

function check_http() {

  local_var port, vers, version, url, buf, concluded;

  port = get_http_port( default:443 );

  url = "/login/login.html";
  buf = http_get_cache( item:url, port:port );

  if( buf =~ "HTTP/1\.. 200" && ( ( "<title>Greenbone Security Assistant" >< buf && "Greenbone OS" >< buf ) ||
      '"title">Greenbone Security Manager</span>' >< buf ) ) {

    vers = "unknown";
    version = eregmatch( string:buf, pattern:'<div class="gos_version">Greenbone OS ([^<]+)</div>', icase:FALSE );

    if( ! isnull( version[1] ) ) {
      vers = version[1];
      concluded = version[0];
    } else {
      version = eregmatch( string:buf, pattern:'<span class="version">Greenbone OS ([^<]+)</span>', icase:FALSE );
      if( ! isnull( version[1] ) ) {
        vers = version[1];
        concluded = version[0];
      } else {
        version = eregmatch( string:buf, pattern:'<span class="version">Version Greenbone OS ([^<]+)</span>', icase:FALSE );
        if( ! isnull( version[1] ) ) {
          vers = version[1];
          concluded = version[0];
        }
      }
    }
    _set_kb_entrys_and_report( version:vers, concluded:concluded, port:port, source:"HTTP banner" );
  }
}

function check_ssh() {

  local_var port, vers, version, uname, concluded, soc, banner;

  ports = get_kb_list( "Services/ssh" );
  if( ! ports ) ports = make_list( 22 );

  foreach port ( ports ) {

    if( get_kb_item( "greenbone/OS" ) ) {
      uname = get_kb_item( "greenbone/OS/uname" );
      if( uname ) {
        version = eregmatch( pattern:'Welcome to the Greenbone OS ([^ ]+) ', string:uname );
        if( ! isnull( version[1] ) && version[1] =~ "^([0-9.-]+)$" ) {
          _set_kb_entrys_and_report( version:version[1], concluded:version[0], port:port, source:"SSH login" );
        } else {
          # GOS 4+ doesn't expose the version in the initial login banner
          _set_kb_entrys_and_report( version:"unknown", concluded:"Welcome to the Greenbone OS", port:port, source:"SSH login" );
        }
      }
    }

    if( get_port_state( port ) ) {

      soc = open_sock_tcp( port );
      if( soc ) {
        # We do not need to login to get the banner.  Until we can
        # switch to libssh 0.6 we use our hacked up version.
        # After the switch we may want to have a login function
        # which terminates the connection right before the KEX
        # protocol part.  This will allows us to get the server
        # banner without a need to try a login.
        banner = ssh_hack_get_server_version( socket:soc );
        close( soc );

        if( banner && "Greenbone OS" >< banner ) {
          version = eregmatch( pattern:"Greenbone OS ([0-9.-]+)", string:banner );
          if( ! isnull( version[1] ) ) {
            _set_kb_entrys_and_report( version:version[1], concluded:version[0], port:port, source:"SSH banner" );
          } else {
            _set_kb_entrys_and_report( version:"unknown", concluded:"Greenbone OS", port:port, source:"SSH banner" );
          }
        }
      }
    }
  }
}

function _set_kb_entrys_and_report( version, concluded, port, source ) {

  local_var version, cpe, concluded, port, source;

  set_kb_item( name:"greenbone/G_OS", value:version );

  cpe = build_cpe( value:version, exp:"^([0-9.-]+)", base:"cpe:/o:greenbone:greenbone_os:" );
  if( isnull( cpe ) )
    cpe = 'cpe:/o:greenbone:greenbone_os';

  register_and_report_os( os:"Greenbone OS", cpe:cpe, banner_type:source, port:port, desc:SCRIPT_DESC, runs_key:"unixoide" );

  log_message( data:build_detection_report( app:"Greenbone OS",
                                            version:version,
                                            install:port + '/tcp',
                                            cpe:cpe,
                                            concluded:concluded ),
                                            port:port );
  exit( 0 );
}

if( ! get_kb_item( "Settings/disable_cgi_scanning" ) ) {
  check_http();
}

check_ssh();

exit( 0 );
