###############################################################################
# OpenVAS Vulnerability Test
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
#
# OpenSSL 'ssl3_get_key_exchange()' Use-After-Free Memory Corruption Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100751");
  script_version("2019-10-02T07:08:50+0000");
  script_tag(name:"last_modification", value:"2019-10-02 07:08:50 +0000 (Wed, 02 Oct 2019)");
  script_tag(name:"creation_date", value:"2010-08-10 14:55:08 +0200 (Tue, 10 Aug 2010)");
  script_bugtraq_id(42306, 44884);
  script_cve_id("CVE-2010-2939", "CVE-2010-3864");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("OpenSSL Multiple Vulnerabilities - Nov10");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20101116.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/42306");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44884");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2010/Aug/84");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_openssl_detect.nasl", "gb_openssl_detect_lin.nasl", "gb_openssl_detect_win.nasl");
  script_mandatory_keys("openssl/detected");

  script_tag(name:"summary", value:"OpenSSL is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist:

  - Multiple race conditions in ssl/t1_lib.c, when multi-threading and internal caching are enabled on a TLS
  server related to the TLS server name extension and elliptic curve cryptography. (CVE-2010-3864)

  - Double free vulnerability in the ssl3_get_key_exchange function in the OpenSSL client (ssl/s3_clnt.c)
  when using ECDH. (CVE-2010-2939)");

  script_tag(name:"impact", value:"- might allow remote attackers execute arbitrary code via client data that
  triggers a heap-based buffer overflow. (CVE-2010-3864)

  - allows context-dependent attackers to cause a denial of service (crash) and possibly execute arbitrary
  code via a crafted private key with an invalid prime. (CVE-2010-2939)");

  script_tag(name:"affected", value:"The issue affects OpenSSL 0.9.8f through 0.9.8o, 1.0.0 and 1.0.0a.");

  script_tag(name:"solution", value:"Update to version 0.9.8p, 1.0.0a or later.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"0.9.8f", test_version2:"0.9.8o") ||
   version_in_range(version:vers, test_version:"1.0.0", test_version2:"1.0.0a")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"0.9.8p/1.0.0a", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
