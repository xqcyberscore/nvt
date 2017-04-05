###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tls_npn_alpn_detect.nasl 5602 2017-03-17 14:11:29Z cfi $
#
# SSL/TLS: NPN / ALPN Extension and Protocol Support Detection
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.108099");
  script_version("$Revision: 5602 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-17 15:11:29 +0100 (Fri, 17 Mar 2017) $");
  script_tag(name:"creation_date", value:"2017-03-15 11:00:00 +0100 (Wed, 15 Mar 2017)");
  script_name("SSL/TLS: NPN / ALPN and Protocol Support Extension Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("gb_tls_version_get.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://tools.ietf.org/html/rfc7301");
  script_xref(name:"URL", value:"https://tools.ietf.org/html/draft-agl-tls-nextprotoneg-04");

  script_tag(name:"summary", value:"This routine identifies services supporting the following extensions to TLS:

  - Application-Layer Protocol Negotiation (ALPN)

  - Next Protocol Negotiation (NPN).

  Based on the availability of this extensions the supported Network Protocols by this service are gathered and reported.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("misc_func.inc");
include("byte_func.inc");
include("ssl_funcs.inc");

npn_report  = 'The remote service advertises support for the following Network Protocol(s) via the NPN extension:\n\nSSL/TLS Protocol:Network Protocol\n';
alpn_report = 'The remote service advertises support for the following Network Protocol(s) via the ALPN extension:\n\nSSL/TLS Protocol:Network Protocol\n';

port = get_http_port( default:443, ignore_broken:TRUE, ignore_cgi_disabled:TRUE );

## Exit on non-ssl http port
if( get_port_transport( port ) < ENCAPS_SSLv23 ) exit( 0 );

if( ! versions = get_supported_tls_versions( port:port, min:SSL_v3 ) ) exit( 0 );

# First check for NPN
foreach version( versions ) {

  if( ! SSL_VER = version_kb_string_mapping[version] ) continue;

  hello_done = FALSE;

  soc = open_ssl_socket( port:port );
  if( ! soc ) continue;

  hello = ssl_hello( version:version, extensions:make_list( "next_protocol_negotiation"  ) );
  if( ! hello ) {
    close( soc );
    continue;
  }

  send( socket:soc, data:hello );

  while( ! hello_done ) {

    data = ssl_recv( socket:soc );

    if( ! data ) {
      close( soc );
      break;
    }

    # Jump out if we're getting an ALERT
    record = search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) );
    if( record ) {
      close( soc );
      break;
    }

    record = search_ssl_record( data:data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
    if( record ) {
      npn_prots = record['extension_npn_supported_protocols'];
      # The server will report all supported protocols via NPN
      foreach npn_prot( npn_prots ) {
        npn_supported = TRUE;
        npn_report += version_string[version] + ":" + npn_alpn_name_mapping[npn_prot] + '\n';
        set_kb_item( name:"tls_npn_supported/" + SSL_VER + "/" + port, value:TRUE );
        set_kb_item( name:"tls_npn_prot_supported/" + SSL_VER + "/" + port, value:npn_prot );
      }
    }

    record = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
    if( record ) {
      hello_done = TRUE;
      break;
    }
  }
}

# Next check for ALPN
foreach version( versions ) {

  if( ! SSL_VER = version_kb_string_mapping[version] ) continue;

  foreach alpn_prot( npn_alpn_protocol_list ) {

    hello_done = FALSE;

    soc = open_ssl_socket( port:port );
    if( ! soc ) continue;

    hello = ssl_hello( version:version, extensions:make_list( "application_layer_protocol_negotiation"  ), alpn_protocol:alpn_prot );
    if( ! hello ) {
      close( soc );
      continue;
    }

    send( socket:soc, data:hello );

    while( ! hello_done ) {

      data = ssl_recv( socket:soc );

      if( ! data ) {
        close( soc );
        break;
      }

      # Jump out if we're getting an ALERT
      record = search_ssl_record( data:data, search:make_array( "content_typ", SSLv3_ALERT ) );
      if( record ) {
        close( soc );
        break;
      }

      record = search_ssl_record( data:data, search: make_array( "handshake_typ", SSLv3_SERVER_HELLO ) );
      if( record ) {
        alpn_prots = record['extension_alpn_supported_protocols'];
        # The server will choose only one protocol via ALPN
        foreach alpn_prot( alpn_prots ) {
          alpn_supported = TRUE;
          alpn_report += version_string[version] + ":" + npn_alpn_name_mapping[alpn_prot] + '\n';
          set_kb_item( name:"tls_alpn_supported/" + SSL_VER + "/" + port, value:TRUE );
          set_kb_item( name:"tls_alpn_prot_supported/" + SSL_VER + "/" + port, value:alpn_prot );
        }
      }

      record = search_ssl_record( data:data, search:make_array( "handshake_typ", SSLv3_SERVER_HELLO_DONE ) );
      if( record ) {
        hello_done = TRUE;
        break;
      }
    }
  }
}

if( alpn_supported || npn_supported ) {
  if( npn_supported )  report += npn_report;
  if( alpn_supported ) report += '\n' + alpn_report;
  log_message( port:port, data:report );
}

exit( 0 );
