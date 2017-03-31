###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_otrs_detect.nasl 2672 2016-02-17 07:38:35Z antu123 $
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
  script_version("$Revision: 2672 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-02-17 08:38:35 +0100 (Wed, 17 Feb 2016) $");
  script_tag(name:"creation_date", value:"2010-02-22 13:34:53 +0100 (Mon, 22 Feb 2010)");
  script_name("Open Ticket Request System (OTRS) and ITSM Version Detection");

  script_tag(name: "summary" , value: "Detection of installed version of
  Open Ticket Request System (OTRS) and ITSM.

  The script sends a connection request to the server and attempts to extract
  the version number from the reply.");

  script_summary("Checks for the presence of Open Ticket Request System (OTRS) and ITSM");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2010 SecPod");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Function to Register Product and Build report
function build_report(app, ver, concluded, cpe, insloc, otrsPort)
{
  register_product(cpe:cpe, location:insloc, port:otrsPort);

  log_message(data: build_detection_report(app:app,
                                           version:ver,
                                           install:insloc,
                                           cpe:cpe,
                                           concluded:concluded),
                                           port:otrsPort);
}

##Get Port
otrsPort = get_http_port( default:80 );

#Iterate possible paths
foreach dir (make_list_unique( "/", "/support", "/OTRS", "/otrs", cgi_dirs( port:otrsPort ) ) ) {

  otrsInstalled = 0;
  install = dir;
  if( dir == "/" ) dir = "";

  foreach path( make_list( "/public.pl", "/index.pl", "/installer.pl" ) ) {

    sndReq = http_get( item: dir + path, port:otrsPort );
    rcvRes = http_keepalive_send_recv( port:otrsPort, data:sndReq, bodyonly:TRUE );

    if( rcvRes && ( egrep( pattern:"Powered by OTRS|Powered by.*OTRS", string:rcvRes ) ) ) {

      otrsInstalled = 1;
      vers = "unknown";

      ## Pattern for OTRS 4 and up
      otrsVer = eregmatch( pattern:'title="OTRS ([0-9.]+)"', string:rcvRes );
      if( otrsVer[1] ) {
        vers = otrsVer[1];
      } else {
        ## Pattern for OTRS 3
        otrsVer = eregmatch( pattern:"Powered by.*>OTRS ([0-9.]+)<", string:rcvRes );
        if( otrsVer[1] ) {
          vers = otrsVer[1];
        } else {
          ## Pattern for OTRS below version 3
          otrsVer = eregmatch( pattern:">Powered by OTRS ([0-9.]+)<", string:rcvRes );
          vers = otrsVer[1];
        }
      }
    }
  }

  if( otrsInstalled ) {

    if( vers != "unknown" ) {
      set_kb_item( name:"www/" + otrsPort + "/OTRS", value:vers + ' under ' + install );
    }

    set_kb_item( name:"OTRS/installed", value:TRUE );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:otrs:otrs:" );
    if( isnull( cpe ) )
       cpe = 'cpe:/a:otrs:otrs';

    ## Register OTRS Product and Build Report
    build_report( app:"OTRS", ver:vers, concluded:otrsVer[0], cpe:cpe, insloc:install, port:otrsPort );
  }

  ## To detect OTRS::ITSM
  rcvRes = http_get_cache( item: dir + "/index.pl", port:otrsPort );

  if( rcvRes && "Welcome to OTRS::ITSM" >< rcvRes ) {

    itsmver = eregmatch( pattern:"Welcome to OTRS::ITSM ([0-9\.\w]+)" , string:rcvRes);

    if( itsmver[1] != NULL ) {
      set_kb_item( name:"www/" + otrsPort + "/OTRS ITSM", value:itsmver[1] + ' under ' + install );
    }

    set_kb_item( name:"OTRS ITSM/installed", value:TRUE );

    cpe = build_cpe( value:itsmver[1], exp:"^([0-9.]+)", base:"cpe:/a:otrs:otrs_itsm:" );
    if( isnull( cpe ) )
        cpe = 'cpe:/a:otrs:otrs_itsm';

    ## Register ITSM Product and Build Report
    build_report( app:"OTRS ITSM", ver:itsmver[1], concluded:itsmver[0], cpe:cpe, insloc:install, port:otrsPort );
  }
}

exit( 0 );
