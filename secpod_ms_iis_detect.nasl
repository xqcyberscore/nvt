###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms_iis_detect.nasl 10826 2018-08-08 07:30:42Z cfischer $
#
# Microsoft IIS Webserver Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900710");
  script_version("$Revision: 10826 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 09:30:42 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Microsoft IIS Webserver Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("IIS/banner");

  script_tag(name:"summary", value:"This script detects the installed Microsoft IIS Webserver and
  sets the result in the KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );
if( ! banner || banner !~ "Server: (Microsoft-)?IIS" ) exit( 0 );

version = "unknown";
install = port + "/tcp";
set_kb_item( name:"IIS/installed", value:TRUE );

vers = eregmatch( pattern:"IIS\/([0-9.]+)", string:banner );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  set_kb_item( name:"IIS/" + port + "/Ver", value:version );
}

cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:iis:" );
if( isnull( cpe ) )
  cpe = "cpe:/a:microsoft:iis";

register_product( cpe:cpe, location:install, port:port, service:"www" );
log_message( data:build_detection_report( app:"Microsoft IIS Webserver",
                                          version:version,
                                          install:install,
                                          cpe:cpe,
                                          concluded:banner ),
                                          port:port );

exit( 0 );