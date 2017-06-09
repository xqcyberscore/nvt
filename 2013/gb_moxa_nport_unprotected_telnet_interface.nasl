###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moxa_nport_unprotected_telnet_interface.nasl 6104 2017-05-11 09:03:48Z teissa $
#
# Moxa NPort Unprotected Telnet Console
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

tag_summary = "The remote Moxa NPort Telnet Console is not protected by a password.";


tag_solution = "Set a password.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.103665";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version ("$Revision: 6104 $");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_name("Moxa NPort Unprotected Telnet Console");

 script_tag(name:"last_modification", value:"$Date: 2017-05-11 11:03:48 +0200 (Thu, 11 May 2017) $");
 script_tag(name:"creation_date", value:"2013-02-19 12:36:40 +0100 (Tue, 19 Feb 2013)");
 script_category(ACT_ATTACK);
 script_tag(name:"qod_type", value:"remote_vul");
 script_family("General");
 script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl");
 script_require_ports("Services/telnet", 23);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("telnet_func.inc");

port = get_kb_item("Services/telnet");
if(!port)port = 23;

if(!get_port_state(port))exit(0);

banner = get_telnet_banner(port:port);

if(!banner || "Basic settings" >!< banner || "Change password" >!< banner || "Load factory default" >!< banner)exit(0);

security_message(port:port);
exit(0);
