###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_mitm_attack_vuln_feb16_lin.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# OpenSSL 'Diffie-Hellman small subgroups' MitM Attack Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = "cpe:/a:openssl:openssl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806674");
  script_version("$Revision: 12096 $");
  script_cve_id("CVE-2016-0701");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-01 16:08:40 +0530 (Mon, 01 Feb 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL 'Diffie-Hellman small subgroups' MitM Attack Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to man-in-the-middle (MitM) attack vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as the primes used in X9.42 style
  parameter files may not be safe. When an application is using Diffie-Hellman
  configured with parameters based on primes that are not safe then an attacker
  could use this fact to find a peer's private DH exponent.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to conduct man-in-the-middle attack.");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.2x before 1.0.2f on
  Linux.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 1.0.2f or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160128.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("OpenSSL/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sslVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(sslVer =~ "^(1\.0\.2)")
{
  if(version_is_less(version:sslVer, test_version:"1.0.2f"))
  {
    report = report_fixed_ver(installed_version:sslVer, fixed_version:"1.0.2f");
    security_message(data:report);
    exit(0);
  }
}
