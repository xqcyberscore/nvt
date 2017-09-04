###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pacific_timesheet_detect.nasl 7006 2017-08-25 11:51:20Z teissa $
#
# Pacific Timesheet Version Detection
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800180");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 7006 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-25 13:51:20 +0200 (Fri, 25 Aug 2017) $");
  script_tag(name:"creation_date", value:"2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Pacific Timesheet Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script is detects the installed version of Pacific Timesheet
  and sets the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

## Get Pacific Timesheet port
port = get_http_port( default:80 );

foreach dir( make_list_unique( "/", "/timesheet", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  ## Send the request and Receive the response
  sndReq = http_get( item: dir + "/about-show.do", port:port );
  rcvRes = http_keepalive_send_recv( port:port, data:sndReq );

  ## Confirm application is Pacific Timesheet
  if( rcvRes =~ "HTTP/1.. 200" && ">About Pacific Timesheet<" >< rcvRes ) {

    version = "unknown";

    ## Get Pacific Timesheet Version
    ver = eregmatch( pattern:">Version ([0-9.]+) [Bb][Uu][Ii][Ll][Dd]"+
                                      " ([0-9]+)</", string:rcvRes );

    if( ver[1] != NULL && ver[2] != NULL ) {
      version = ver[1] + "." + ver[2];
    }

    tmp_version = version + " under " + install;
    set_kb_item(name:"www/" + port + "/pacificTimeSheet/Ver", value:tmp_version);

    ## build cpe and store it as host_detail
    cpe = build_cpe( value: version, exp:"^([0-9.]+)", base:"cpe:/a:pacifictimesheet:pacific_timesheet:" );
    if( isnull( cpe ) )
      cpe = 'cpe:/a:pacifictimesheet:pacific_timesheet';

    ## Register Product and Build Report
    register_product( cpe:cpe, location:install, port:port );

    log_message( data: build_detection_report( app:"Pacific Timesheet",
                                               version:version,
                                               install:install,
                                               cpe:cpe,
                                               concluded:ver[0] ),
                                               port:port );
  }
}

exit( 0 );