###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_xampp_detect.nasl 2685 2016-02-17 17:15:28Z cfi $
#
# XAMPP Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-10-16
# According to new format
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900526");
  script_version("$Revision: 2685 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-02-17 18:15:28 +0100 (Wed, 17 Feb 2016) $");
  script_tag(name:"creation_date", value:"2009-03-30 15:53:34 +0200 (Mon, 30 Mar 2009)");
  script_name("XAMPP Version Detection");
  script_summary("Set the Version of XAMPP in KB");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script finds the installed XAMPP
  version and saves the version in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );

if( ! can_host_php( port:port ) ) exit( 0 );

foreach dir( make_list_unique( "/", "/xampp", cgi_dirs( port:port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  rcvRes = http_get_cache( item: dir + "/index.php", port:port );

  if( rcvRes !~ "HTTP/1.. 200" && "XAMPP" >!< rcvRes ) {
    rcvRes = http_get_cache( item: dir + "/start.php", port:port );
  }

  if( rcvRes =~ "HTTP/1.. 200" && "XAMPP" >< rcvRes ) {

    version = "unknown";

    ver = eregmatch( pattern:"XAMPP.* ([0-9.]+)", string:rcvRes );
    if( ver[1] != NULL ) version = ver[1];

    set_kb_item( name:"www/" + port + "/XAMPP", value:version );
    set_kb_item( name:"xampp/installed", value:TRUE );

    ## build cpe and store it as host_detail
    cpe = build_cpe(value:version, exp:"^([0-9.]+)", base:"cpe:/a:apachefriends:xampp:");
    if( isnull( cpe ) )
      cpe = 'cpe:/a:apachefriends:xampp';

    register_product( cpe:cpe, location:install, port:port );

    log_message( data:build_detection_report( app:"XAMPP",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:ver[0] ),
                                              port:port );
  }
}

exit( 0 );