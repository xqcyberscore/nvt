###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_proxmox_ve_detect.nasl 5505 2017-03-07 10:00:18Z teissa $
#
# Proxmox Virtual Environment Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, https://www.schutzwerk.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.111090");
  script_version("$Revision: 5505 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-07 11:00:18 +0100 (Tue, 07 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-03-17 10:42:39 +0100 (Thu, 17 Mar 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Proxmox Virtual Environment Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 3128, 8006);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The script sends a HTTP request to the server and
  attempts to identify a Proxmox Virtual Environmentfrom the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("cpe.inc");

port = get_http_port( default:8006 );
banner = get_http_banner( port:port );
buf = http_get_cache( item:"/", port:port );

if( "erver: pve-api-daemon" >< banner || "Proxmox Virtual Environment</title>" >< buf || 
    "/pve2/css/ext-pve.css" >< buf || ( "PVE.UserName" >< buf && "PVE.CSRFPreventionToken" >< buf ) ) {

  version = "unknown";
  install = "/";
  set_kb_item( name:"www/" + port + "/ProxmoxVE", value:version );
  set_kb_item( name:"ProxmoxVE/installed", value:TRUE );

  # CPE not registered yet
  cpe = 'cpe:/a:proxmox:ve';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Proxmox Virtual Environment",
                                                 version:version,
                                                 install:install,
                                                 cpe:cpe ),
                                                 port:port );
}

exit( 0 );
