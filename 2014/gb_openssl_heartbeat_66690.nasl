###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_heartbeat_66690.nasl 5525 2017-03-09 08:40:36Z cfi $
#
# SSL/TLS: OpenSSL TLS 'heartbeat' Extension Information Disclosure Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103936");
  script_version("$Revision: 5525 $");
  script_bugtraq_id(66690);
  script_cve_id("CVE-2014-0160");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-09 09:40:36 +0100 (Thu, 09 Mar 2017) $");
  script_tag(name:"creation_date", value:"2014-04-09 09:54:09 +0200 (Wed, 09 Apr 2014)");
  script_name("SSL/TLS: OpenSSL TLS 'heartbeat' Extension Information Disclosure Vulnerability");
  script_category(ACT_ATTACK);
  script_family("SSL and TLS");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_tls_version_get.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66690");
  script_xref(name:"URL", value:"http://openssl.org/");

  tag_insight = "The TLS and DTLS implementations do not properly handle
  Heartbeat Extension packets.";

  tag_impact = "An attacker can exploit this issue to gain access to sensitive
  information that may aid in further attacks.";

  tag_affected = "OpenSSL 1.0.1f, 1.0.1e, 1.0.1d, 1.0.1c, 1.0.1b, 1.0.1a, and
  1.0.1 are vulnerable.";

  tag_summary = "OpenSSL is prone to an information disclosure vulnerability.";

  tag_solution = "Updates are available.";

  tag_vuldetect = "Send a special crafted TLS request and check the response.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"vuldetect", value:tag_vuldetect);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");
include("ssl_funcs.inc");
include("gb_openssl_heartbeat.inc");

port = get_ssl_port();
if( ! port ) exit( 0 );

if( ! versions = get_supported_tls_versions( port:port, min:SSL_v3 ) ) exit( 0 );

foreach version( versions ) {
  test_hb( port:port, version:version );
}

exit( 99 );
