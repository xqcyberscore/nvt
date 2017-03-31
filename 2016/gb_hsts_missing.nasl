###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hsts_missing.nasl 5426 2017-02-26 17:47:00Z cfi $
#
# SSL/TLS: HTTP Strict Transport Security (HSTS) Missing
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105879");
  script_version("$Revision: 5426 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-26 18:47:00 +0100 (Sun, 26 Feb 2017) $");
  script_tag(name:"creation_date", value:"2016-08-22 13:07:41 +0200 (Mon, 22 Aug 2016)");
  script_name("SSL/TLS: HTTP Strict Transport Security (HSTS) Missing");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_hsts_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("hsts/missing/port");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet");

  script_tag(name:"summary", value:"The remote web server is not enforcing HSTS.");
  script_tag(name:"solution", value:"Enable HSTS.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

if( ! port = get_kb_item( "hsts/missing/port" ) ) exit( 0 );

banner = get_kb_item( "www/banner/" + port + "/" );

# Clean-up Banner from dynamic data so we don't report differences on the delta report
pattern = "(Date: |expires=|Expires: |PHPSESSID=|Last-Modified: |Content-Length: |Set-Cookie: |Etag: |SessionId=)([0-9a-zA-Z\ \:\,\-\;=]+)";
if( eregmatch( pattern:pattern, string:banner ) ) {
  banner = ereg_replace( string:banner, pattern:pattern, replace:"\1***replaced***" );
}

log_message( port:port, data:'The remote web server is not enforcing HSTS\n\nHTTP-Banner:\n\n' + banner );

exit( 0 );
