###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_ccs_starttls_67899.nasl 4679 2016-12-05 15:50:24Z cfi $
#
# OpenSSL CCS Man in the Middle Security Bypass Vulnerability (STARTTLS Check)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105043");
  script_version("$Revision: 4679 $");
  script_bugtraq_id(67899);
  script_cve_id("CVE-2014-0224");
  script_name("OpenSSL CCS Man in the Middle Security Bypass Vulnerability (STARTTLS Check)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-12-05 16:50:24 +0100 (Mon, 05 Dec 2016) $");
  script_tag(name:"creation_date", value:"2014-06-10 17:18:54 +0200 (Tue, 10 Jun 2014)");
  script_category(ACT_ATTACK);
  script_family("General");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_starttls_pop3.nasl", "gb_starttls_imap.nasl", "gb_starttls_ftp.nasl", "gb_starttls_smtp.nasl",
                      "gb_postgres_tls_support.nasl", "gb_starttls_xmpp.nasl", "gb_starttls_nntp.nasl", "gb_starttls_ldap.nasl");
  script_mandatory_keys("ssl_tls/port");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67899");
  script_xref(name:"URL", value:"http://openssl.org/");

  tag_insight = "OpenSSL does not properly restrict processing of ChangeCipherSpec
  messages, which allows man-in-the-middle attackers to trigger use of a
  zero-length master key in certain OpenSSL-to-OpenSSL communications, and
  consequently hijack sessions or obtain sensitive information, via a crafted
  TLS handshake, aka the 'CCS Injection' vulnerability.";

  tag_impact = "Successfully exploiting this issue may allow attackers to obtain
  sensitive information by conducting a man-in-the-middle attack. This
  may lead to other attacks.";

  tag_affected = "OpenSSL before 0.9.8za,
  1.0.0 before 1.0.0m and
  1.0.1 before 1.0.1h";

  tag_summary = "OpenSSL is prone to security-bypass vulnerability.

  This NVT has been merged into the NVT 'OpenSSL CCS Man in the Middle Security Bypass Vulnerability' (OID: 1.3.6.1.4.1.25623.1.0.105042).";

  tag_solution = "Updates are available.";

  tag_vuldetect = "Send two SSL ChangeCipherSpec request and check the response.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"vuldetect", value:tag_vuldetect);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit( 66 );
