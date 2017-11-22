###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_untrusted_ca_detect.nasl 7844 2017-11-21 11:02:43Z jschulte $
#
# Untrusted SSL/TLS Certificate Authorities
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
  script_oid("1.3.6.1.4.1.25623.1.0.113054");
  script_version("$Revision: 7844 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-21 12:02:43 +0100 (Tue, 21 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-11-21 10:13:14 +0100 (Tue, 21 Nov 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Untrusted SSL/TLS Certificate Authorities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SSL and TLS");
  script_dependencies("ssl_cert_details.nasl");
  script_mandatory_keys("ssl/cert/avail");

  script_tag(name:"summary", value:"The service is using a TLS/SSL certificate from a known bad certificate authority. An attacker could use this for MitM attacks, accessing sensible data and other attacks.");
  script_tag(name:"vuldetect", value:"The script reads the certificate the target host is using and checks if it was signed by an untrusted certificate authority.");
  script_tag(name:"solution", value:"Replace the SSL/TLS certificate with a trusted one.");

  script_xref(name:"URL", value:"https://badssl.com");

  exit( 0 );
}

authorities = get_kb_list( "HostDetails/Cert/*/issuer" );

untrusted_authorities = make_list(  "StartCom", "startcom", "startCom",
                                    "superfish", "SuperFish", "Superfish",
                                    "edellroot", "eDellRoot",
                                    "dsdtestprovider", "DSDTestProvider", "DSD Test Provider",
                                    "preact-cli", "Preact-CLI", "Preact CLI", "Acme Co", "acme co",
                                    "webpack-dev-server", "Webpack Dev Server", "webpack dev server", "localhost" );

foreach ca ( authorities ) {
  foreach pattern ( untrusted_authorities ) {
    if( pattern >< ca ) {
      VULN = TRUE;
      untrusted_findings = make_list( untrusted_findings, ca );
      break;
    }
  }
}

if( VULN ) {
  message = "Certificates signed by the following untrusted Certificate Authorities were found on the target host: ";
  foreach ca ( untrusted_findings ) {
    message += '\r\n' + ca;
  }
  security_message( port: 0, data: message );
  exit( 0 );
}

exit ( 99 );
