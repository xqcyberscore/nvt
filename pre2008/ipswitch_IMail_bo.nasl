###############################################################################
# OpenVAS Vulnerability Test
# $Id: ipswitch_IMail_bo.nasl 6040 2017-04-27 09:02:38Z teissa $
#
# ipswitch IMail DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14684");
  script_version("$Revision: 6040 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-27 11:02:38 +0200 (Thu, 27 Apr 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-2422", "CVE-2004-2423");
  script_bugtraq_id(11106);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("ipswitch IMail DoS");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl", "no404.nasl");
  script_mandatory_keys("Ipswitch/banner");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "The remote host is running IMail web interface.  This version contains 
  multiple buffer overflows.";

  tag_impact = "An attacker could use these flaws to remotly crash the service 
  accepting requests from users, or possibly execute arbitrary code.";

  tag_solution = "Upgrade to IMail 8.13 or newer.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );

banner = get_http_banner( port:port );
if( ! banner ) exit( 0 );

serv = egrep( string:banner, pattern:"^Server:.*" );
if( ereg( pattern:"^Server:.*Ipswitch-IMail/([1-7]\..*|(8\.(0[0-9]?[^0-9]|1[0-2][^0-9])))", string:serv ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
