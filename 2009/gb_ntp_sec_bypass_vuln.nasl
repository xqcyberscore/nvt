###############################################################################
# OpenVAS Vulnerability Test
#
# NTP EVP_VerifyFinal() Security Bypass Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800408");
  script_version("2019-09-24T10:41:39+0000");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2009-01-15 16:11:17 +0100 (Thu, 15 Jan 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-0021");
  script_bugtraq_id(33150);
  script_name("NTP.org 'ntpd' EVP_VerifyFinal() Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/499827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/499855");
  script_xref(name:"URL", value:"http://www.ocert.org/advisories/ocert-2008-016.html");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to bypass the certificate
  validation checks and can cause spoofing attacks via signature checks on DSA
  and ECDSA keys used with SSL/TLS.");

  script_tag(name:"affected", value:"NTP.org's ntpd version 4.2.4 to 4.2.4p5 and 4.2.5 to 4.2.5p150.");

  script_tag(name:"insight", value:"The flaw is due to improper validation of return value in
  EVP_VerifyFinal function of openssl.");

  script_tag(name:"solution", value:"Upgrade to NTP.org's ntpd version 4.2.4p6 or 4.2.5p151.");

  script_tag(name:"summary", value:"The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to a security bypass vulnerability.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port))
  exit(0);

if(!version = infos["version"])
  exit(0);

location = infos["location"];
proto = infos["proto"];

if(((revcomp(a:version, b:"4.2.4") >= 0) && (revcomp(a:version, b:"4.2.4p5") <= 0)) ||
   ((revcomp(a:version, b:"4.2.5") >= 0) && (revcomp(a:version, b:"4.2.5p150") <= 0))) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.2.4p6 or 4.2.5p151", install_path:location);
  security_message(port:port, proto:proto, data:report);
  exit(0);
}

exit(99);
