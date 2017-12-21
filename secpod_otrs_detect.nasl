###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_otrs_detect.nasl 8206 2017-12-21 07:17:57Z cfischer $
#
# Open Ticket Request System (OTRS) and ITSM Version Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-12-24
# To detect latest version OTRS 4
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902018");
  script_version("$Revision: 8206 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:17:57 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_name("Open Ticket Request System (OTRS) and ITSM Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2010 SecPod");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection of installed version of
  Open Ticket Request System (OTRS) and ITSM.

  The script sends a connection request to the server and attempts to extract
  the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/support", "/OTRS", "/otrs", cgi_dirs( port:port ) ) ) {

  otrsInstalled = FALSE;
  install = dir;
  if( dir == "/" ) dir = "";

  foreach path( make_list( "/public.pl", "/index.pl", "/installer.pl" ) ) {

    req = http_get( item:dir + path, port:port );
    res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

    if( res && ( egrep( pattern:"Powered by OTRS|Powered by.*OTRS", string:res ) ) ) {

      otrsInstalled = TRUE;
      vers = "unknown";

      ## Pattern for OTRS 4 and up
      otrsVer = eregmatch( pattern:'title="OTRS ([0-9.]+)"', string:res );
      if( otrsVer[1] ) {
        vers = otrsVer[1];
      } else {
        ## Pattern for OTRS 3
        otrsVer = eregmatch( pattern:"Powered by.*>OTRS ([0-9.]+)<", string:res );
        if( otrsVer[1] ) {
          vers = otrsVer[1];
        } else {
          ## Pattern for OTRS below version 3
          otrsVer = eregmatch( pattern:">Powered by OTRS ([0-9.]+)<", string:res );
          vers = otrsVer[1];
        }
      }
    }
  }

  if( otrsInstalled ) {

    if( vers != "unknown" ) {
      set_kb_item( name:"www/" + port + "/OTRS", value:vers + ' under ' + install );
    }

    set_kb_item( name:"OTRS/installed", value:TRUE );
    register_and_report_cpe( app:"OTRS", ver:vers, concluded:otrsVer[0], base:"cpe:/a:otrs:otrs:", expr:"^([0-9.]+)", insloc:install, regPort:port );
  }

  ## To detect OTRS::ITSM
  res = http_get_cache( item:dir + "/index.pl", port:port );

  if( res && "Welcome to OTRS::ITSM" >< res ) {

    vers = "unknown";
    itsmver = eregmatch( pattern:"Welcome to OTRS::ITSM ([0-9\.\w]+)", string:res );

    if( itsmver[1] ) {
      vers = itsmver[1];
      set_kb_item( name:"www/" + port + "/OTRS ITSM", value:vers + ' under ' + install );
    }

    set_kb_item( name:"OTRS ITSM/installed", value:TRUE );
    register_and_report_cpe( app:"OTRS ITSM", ver:vers, concluded:itsmver[0], base:"cpe:/a:otrs:otrs_itsm:", expr:"^([0-9.]+)", insloc:install, regPort:port );
  }
}

exit( 0 );
