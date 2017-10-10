###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpkp_detect.nasl 7385 2017-10-09 12:02:13Z cfischer $
#
# SSL/TLS: HTTP Public Key Pinning (HPKP) Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108245");
  script_version("$Revision: 7385 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-09 14:02:13 +0200 (Mon, 09 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-09 08:07:41 +0200 (Mon, 09 Oct 2017)");
  script_name("SSL/TLS: HTTP Public Key Pinning (HPKP) Detection");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  # nb: Don't add a dependency to http_version.nasl to allow a minimal SSL/TLS check configuration
  script_dependencies("find_service.nasl", "httpver.nasl", "gb_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project");
  script_xref(name:"URL", value:"https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#hpkp");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7469");
  script_xref(name:"URL", value:"https://securityheaders.io/");

  script_tag(name:"summary", value:"This script checks if the remote HTTPS server has HPKP enabled.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:443, ignore_cgi_disabled:TRUE );
if( get_port_transport( port ) < ENCAPS_SSLv23 ) exit( 0 );

banner = get_http_banner( port:port );
# We should not expect a HSTS header without a 20x or 30x.
# nb: Nginx is e.g. only sending an header on 200, 201, 204, 206, 301, 302, 303, 304 and 307
if( ! banner || banner !~ "^HTTP/1\.[01] [23]0[0-7]" ) exit( 0 );

if( ! pkp = egrep( pattern:'^Public-Key-Pins: ', string:banner, icase:TRUE ) ) { # Public-Key-Pins-Report-Only is used for testing only
  replace_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  exit( 0 );
}

# max-age is required: https://tools.ietf.org/html/rfc7469#page-19
# Assume a missing HPKP if its not specified
if( "max-age=" >!< tolower( pkp ) ) {
  replace_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  set_kb_item( name:"hpkp/max_age/missing/" + port, value:TRUE );
  set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );
  exit( 0 );
}

# Assuming missing support if value is set to zero
if( "max-age=0" >< tolower( pkp ) ) {
  replace_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  set_kb_item( name:"hpkp/max_age/zero/" + port, value:TRUE );
  set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );
  exit( 0 );
}

# Assuming missing support if no pin-sha256= is included
# Currently only pin-sha256 is supported / defined but this might change in the future
if( "pin-sha256=" >!< tolower( pkp ) ) {
  replace_kb_item( name:"hpkp/missing", value:TRUE );
  set_kb_item( name:"hpkp/missing/port", value:port );
  set_kb_item( name:"hpkp/pin/missing/" + port, value:TRUE );
  set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );
  exit( 0 );
}

set_kb_item( name:"hpkp/" + port + "/banner", value:pkp );

if( "includesubdomains" >!< tolower( pkp ) ) {
  replace_kb_item( name:"hpkp/includeSubDomains/missing", value:TRUE );
  set_kb_item( name:"hpkp/includeSubDomains/missing/port", value:port );
}

ma = eregmatch( pattern:'max-age=([0-9]+)', string:pkp, icase:TRUE );

if( ! isnull( ma[1] ) )
  set_kb_item( name:"hpkp/max_age/" + port, value:ma[1] ); # TODO: We could give some recommendation about a sensible max-age here

log_message( port:port, data:'The remote HTTPS server is sending the "HTTP Public Key Pinning" header.\n\nHPKP-Header:\n\n' + pkp );
exit( 0 );
