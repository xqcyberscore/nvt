###############################################################################
# OpenVAS Vulnerability Test
#
# Ecessa ShieldLink/PowerLink Detection (Telnet)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.113224");
  script_version("2019-06-06T07:39:31+0000");
  script_tag(name:"last_modification", value:"2019-06-06 07:39:31 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2018-07-06 10:41:45 +0200 (Fri, 06 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ecessa ShieldLink/PowerLink Detection (Telnet)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/ecessa/shield_power_link/detected");

  script_tag(name:"summary", value:"Checks if the target is an Ecessa ShieldLink
  or PowerLink device, and, if so, retrieves the version using Telnet.");

  script_xref(name:"URL", value:"https://www.ecessa.com/powerlink/");
  script_xref(name:"URL", value:"https://www.ecessa.com/powerlink/product_comp_shieldlink/");

  exit(0);
}

include("host_details.inc");
include("telnet_func.inc");
include("misc_func.inc");
include("dump.inc");

port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if( ! banner ) exit( 0 );

if( banner =~ 'ShieldLink' ) {
  kb_base = 'ecessa_shieldlink';
}
else if ( banner =~ 'PowerLink' ) {
  kb_base = 'ecessa_powerlink';
}
else {
  exit( 0 );
}

set_kb_item( name: "ecessa_link/detected", value: TRUE );
set_kb_item( name: kb_base + "/detected", value: TRUE );
set_kb_item( name: kb_base + "/telnet/port", value: port );
set_kb_item( name: kb_base + "/telnet/concluded", value: banner );

version = "unknown";

vers = eregmatch( string: banner, pattern: 'Version ([0-9.]+)' );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
}

set_kb_item( name: kb_base + "/telnet/version", value: version );

exit( 0 );