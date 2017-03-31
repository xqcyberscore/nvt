###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ssl_weak_hash_algo.nasl 4781 2016-12-16 09:12:08Z cfi $
#
# SSL/TLS: Certificate Signed Using A Weak Signature Algorithm
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.105880");
  script_version("$Revision: 4781 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-16 10:12:08 +0100 (Fri, 16 Dec 2016) $");
  script_tag(name:"creation_date", value:"2016-08-22 17:35:50 +0200 (Mon, 22 Aug 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_tag(name:"cvss_base", value:"4.0");
  script_name("SSL/TLS: Certificate Signed Using A Weak Signature Algorithm");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_ssl_cert_chain_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"https://blog.mozilla.org/security/2014/09/23/phasing-out-certificates-with-sha-1-based-signature-algorithms/");

  script_tag(name:"insight", value:"Secure Hash Algorithm 1 (SHA-1) is considered cryptographically weak and not secure enough for ongoing use. Beginning as late as January 2017
  and as early as June 2016, browser developers such as Microsoft and Google will begin warning users when users visit web sites that use SHA-1 signed Secure Socket Layer (SSL)
  certificates.");

  script_tag(name:"solution", value:"Servers that use SSL/TLS certificates signed using an SHA-1 signature will need to obtain new SHA-2 signed SSL/TLS certificates to avoid these
  web browser SSL/TLS certificate warnings.");

  script_tag(name:"vuldetect", value:"Check which algorithm was used to sign the remote SSL/TLS Certificate.");

  script_tag(name:"summary", value:"The remote service is using a SSL/TLS certificate chain that has been signed using a cryptographically weak hashing algorithm.");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("ssl_funcs.inc");
include("CAs.inc");
include("byte_func.inc");
include("http_func.inc");

bad_algos = make_list( "md2WithRSAEncryption", "md4WithRSAEncryption", "md5WithRSAEncryption", "sha1WithRSAEncryption" );

function check_algos ( port )
{
  if( ! c = get_kb_list( "cert_chain/" + port + "/*") ) exit( 0 );

  algos = make_list();

  foreach f ( c )
  {
    f = base64_decode( str:f );

    if( ! certobj = cert_open( f ) )
      continue;

    fpr_sha_1 = cert_query( certobj, "fpr-sha-1" );

    if( fpr_sha_1 && is_known_rootCA( fingerprint:fpr_sha_1 ) )
      continue;

    subject = cert_query( certobj, "subject" );
    if( algorithm_name = cert_query( certobj, "algorithm-name" ) ) algos = make_list( algos, subject +'>##<' + algorithm_name );
  }

  if( algos ) return make_list_unique( algos );

  return;

}

if( ! port = get_ssl_port() ) exit( 0 );

if( ret = check_algos( port:port ) )
{
  vuln = FALSE;
  foreach a ( ret )
  {
    sa = split( a, sep:">##<", keep:FALSE );

    algo = sa[1];
    subj = sa[0];

    if( in_array( search:algo, array:bad_algos ) )
    {
      vuln = TRUE;
      report_algos += 'Subject:              ' + subj +'\nSignature Algorithm:  ' + algo + '\n\n';
    }
  }

  if( vuln )
  {
    report = 'The following certificates are part of the certificate chain but using insecure signature algorithms:\n\n' + report_algos;
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
