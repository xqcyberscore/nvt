###############################################################################
# OpenVAS Vulnerability Test
# $Id: DDI_Compaq_Mgmt_Proxy.nasl 9445 2018-04-11 12:46:27Z cfischer $
#
# Compaq Web Based Management Agent Proxy Vulnerability
#
# Authors:
# H D Moore <hdmoore@digitaldefense.net>
#
# Copyright:
# Copyright (C) 2002 Digital Defense Inc.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10963");
  script_version("$Revision: 9445 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-11 14:46:27 +0200 (Wed, 11 Apr 2018) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-0374");
  script_name("Compaq Web Based Management Agent Proxy Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Digital Defense Inc.");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 2301);
  script_require_keys("www/compaq");

  tag_summary = "This host is running the Compaq Web Management Agent.
  This service can be used as a HTTP proxy. An attacker can use this
  to bypass firewall rules or hide the source of web-based attacks.";

  tag_solution = "Due to the information leak associated with this service,
  we recommend that you disable the Compaq Management Agent or filter access to
  TCP ports 2301 and 280.

  If this service is required, installing the appropriate upgrade from Compaq
  will fix this issue. The software update for your operating system and hardware
  can be found via Compaq's support download page:
  http://www.compaq.com/support/files/server/us/index.html

  For more information, please see the vendor advisory at:
  http://www.compaq.com/products/servers/management/SSRT0758.html";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:2301 );

req = string( "GET http://127.0.0.1:2301/ HTTP/1.0\r\n\r\n" );
res = http_keepalive_send_recv( port:port, data:req );

if( "Compaq WBEM Device Home" >< res ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
