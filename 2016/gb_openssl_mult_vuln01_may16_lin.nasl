###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_mult_vuln01_may16_lin.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# OpenSSL Multiple Vulnerabilities -01 May16 (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.807570");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-2176", "CVE-2016-2109", "CVE-2016-2106", "CVE-2016-2107",
                "CVE-2016-2105");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-05-02 12:46:24 +0530 (Mon, 02 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL Multiple Vulnerabilities -01 May16 (Linux)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - An integer overflow in the EVP_EncryptUpdate function in crypto/evp/evp_enc.c
  script in OpenSSL.
  - An integer overflow in the EVP_EncodeUpdate function in crypto/evp/encode.c
  script in OpenSSL.
  - An error in the 'asn1_d2i_read_bio' function in crypto/asn1/a_d2i_fp.c script
  in the ASN.1 BIO implementation in OpenSSL.
  - An error in 'X509_NAME_oneline' function in crypto/x509/x509_obj.c in OpenSSL.
  - A MITM attacker can use a padding oracle attack to decrypt traffic
  when the connection uses an AES CBC cipher and the server support AES-NI.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to conduct mitm attack, gain access to potentially sensitive information,
  and cause denial of service condition.

  Impact Level: Application");

  script_tag(name:"affected", value:"OpenSSL versions 1.0.1 before 1.0.1t 
  and 1.0.2 before 1.0.2h on Linux.");

  script_tag(name:"solution", value:"Upgrade to OpenSSL 1.0.1t or 1.0.2h or 
  later. For updates refer to https://www.openssl.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.openssl.org/news/secadv/20160503.txt");
  script_xref(name : "URL" , value : "https://mta.openssl.org/pipermail/openssl-announce/2016-April/000069.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("OpenSSL/installed","Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
sslVer = "";

## Get Version
if(!sslVer = get_app_version(cpe:CPE)){
  exit(0);
}

## Checking for Vulnerable version
if(sslVer =~ "^(1\.0\.1)")
{
  if(version_is_less(version:sslVer, test_version:"1.0.1t"))
  {
    fix = "1.0.1t";
    VULN = TRUE;
  }
}

else if(sslVer =~ "^(1\.0\.2)")
{
  if(version_is_less(version:sslVer, test_version:"1.0.2h"))
  {
    fix = "1.0.2h";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = report_fixed_ver(installed_version:sslVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
