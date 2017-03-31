###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hsts_detect.nasl 5472 2017-03-03 07:46:56Z cfi $
#
# SSL/TLS: HTTP Strict Transport Security (HSTS) Detection
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105876");
  script_version("$Revision: 5472 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-03 08:46:56 +0100 (Fri, 03 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-08-22 13:07:41 +0200 (Mon, 22 Aug 2016)");
  script_name("SSL/TLS: HTTP Strict Transport Security (HSTS) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  # nb: Don't add a dependency to http_version.nasl to allow a minimal SSL/TLS check configuration
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/HTTP_Strict_Transport_Security_Cheat_Sheet");

  script_tag(name:"summary", value:"This script checks if the remote HTTPS server has HSTS enabled.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443 );

if( get_port_transport( port ) < ENCAPS_SSLv23 ) exit( 0 );

banner = get_http_banner( port:port );

if( ! banner || banner !~ "HTTP/1\.. 200" ) exit( 0 ); # We should not expect a HSTS header without a 200 OK

if( ! sts = egrep( pattern:'^Strict-Transport-Security: max-age=', string:banner ) ) # TBD: max-age also case-insensitive?
{
  set_kb_item( name:"hsts/missing", value:TRUE );
  set_kb_item( name:"hsts/missing/port", value:port );
  exit( 0 );
}

set_kb_item( name:"hsts/" + port + "/banner", value:sts );

if( "includesubdomains" >!< tolower( sts ) )
{
  set_kb_item(name:"hsts/includeSubDomains/missing", value:TRUE );
  set_kb_item(name:"hsts/includeSubDomains/missing/port", value:port );
}

if( "preload" >!< tolower( sts ) )
{
  set_kb_item(name:"hsts/preload/missing", value:TRUE );
  set_kb_item(name:"hsts/preload/missing/port", value:port );
}

ma = eregmatch( pattern:'max-age=([0-9]+)', string:sts );

if( ! isnull( ma[1] ) )
  set_kb_item(name:"hsts/max_age/" + port, value:ma[1] );

log_message( port:port, data:'The remote HTTPS server send the "HTTP Strict-Transport-Security" header.\n\nSTS-Header: ' + sts);

exit( 0 );
