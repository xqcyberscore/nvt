###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lantronix_unprotected_telnet.nasl 7868 2017-11-22 14:14:30Z asteins $
#
# Lantronix Device Server Unprotected Telnet Access
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112132");
  script_version("$Revision: 7868 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-22 15:14:30 +0100 (Wed, 22 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-22 11:46:00 +0100 (Wed, 22 Nov 2017)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Lantronix Device Server Unprotected Telnet Access");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 9999);

  script_tag(name:"summary", value:"The Lantronix Device Server setup is accessible via an unprotected telnet connection.");
  script_tag(name:"impact", value:"Successful exploitation allows an attacker to configure and control the device.");
  script_tag(name:"solution", value:"Disable the telnet access or protect it via a strong password.");

  exit(0);
}

include("misc_func.inc");
include("telnet_func.inc");

port = get_telnet_port(default:9999);
recv = get_telnet_banner(port:port);

if (recv && "*** Lantronix" >< recv && "Device Server ***" >< recv && "Press Enter" >< recv && "Setup Mode" >< recv) {
  report = "The Lantronix Device Server setup menu could be accessed via an unprotected telnet connection.";
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
