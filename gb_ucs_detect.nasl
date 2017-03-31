###############################################################################
# OpenVAS Vulnerability Test
#
# Univention Corporate Server (UCS) Detection
#
# Authors:
# Michael Wiegand <michael.wiegand@greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103979");
  script_version("$Revision: 5435 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-27 14:35:00 +0100 (Mon, 27 Feb 2017) $");
  script_tag(name:"creation_date", value:"2011-08-01 14:27:02 +0200 (Mon, 01 Aug 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Univention Corporate Server Detection");
  script_family("Product detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_require_ports("Services/www", 80);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Univention/banner");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script attempts to determine if the target is a Univention
  Corporate Server (UCS).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

if( "Univention" >!< banner ) {
  exit( 0 );
} else {
  register_and_report_os( os:"Univention Corporate Server", cpe:"cpe:/o:univention:ucs", banner_type:"HTTP banner", port:port, desc:"Univention Corporate Server Detection" );
  log_message( port:port, data:"The target seems to be running a Univention Corporate Server (UCS)." );
  exit( 0 );
}
