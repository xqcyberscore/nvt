###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_expect-ct_detect.nasl 7697 2017-11-08 11:58:32Z jschulte $
#
# SSL/TLS: Expect Certificate Transparency (Expect-CT) Detection
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113045");
  script_version("$Revision: 7697 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-08 12:58:32 +0100 (Wed, 08 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-07 10:06:44 +0100 (Tue, 07 Nov 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SSL/TLS: Expect Certificate Transparency (Expect-CT) Detection");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_tag(name:"summary", value:"This script checks if the HTTP Server has Expect-CT enabled.");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#ect");
  script_xref(name:"URL", value:"https://scotthelme.co.uk/a-new-security-header-expect-ct/");

  exit( 0 );
}

include( "http_func.inc" );
include( "http_keepalive.inc" );

port = get_http_port( default: 443, ignore_cgi_disabled: TRUE );

banner = get_http_banner( port );

if( ect = egrep( pattern: "Expect-CT:", string: banner, icase: TRUE ) )
{
  set_kb_item( name: "expect-ct/available", value: TRUE );
  log_message( port: port, data: 'The remote HTTPS server is sending the "Expect Certificate Transparency" header.' );
  exit( 0 );
}

set_kb_item( name: "expect-ct/missing", value: TRUE );
exit( 0 );
