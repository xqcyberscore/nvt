###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_sec_bypass_vuln_lin.nasl 8291 2018-01-04 09:51:36Z asteins $
#
# OpenSSL Security Bypass Vulnerability - DEC 2017 (Linux)
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.107260");
  script_version("$Revision: 8291 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 10:51:36 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2017-12-08 12:22:37 +0100 (Fri, 08 Dec 2017)");
  script_cve_id("CVE-2017-3737");
  script_bugtraq_id(102103);

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL Security Bypass Vulnerability - DEC 2017 (Linux)");
  script_tag(name: "summary", value: "This host is running OpenSSL and is prone
  to Security Bypass vulnerability.");
  script_tag(name: "vuldetect", value: "Get the installed version with the help of detect
             NVT and check if the version is vulnerable or not.");

  script_tag(name: "insight", value: "When SSL_read()/SSL_write() is subsequently called by the 
application for the same SSL object then it will succeed and the data is passed without being 
decrypted/encrypted directly from the SSL/TLS record layer.");

  script_tag(name: "impact" , value: "Successfully exploiting this issue will allow attackers 
    to bypass security restrictions and perform unauthorized actions  this may aid in launching 
    further attacks.");

  script_tag(name: "affected", value: "OpenSSL 1.0.2 (starting from version 1.0.2b) before 1.0.2n");
  script_tag(name: "solution", value: "OpenSSL 1.0.2 users should upgrade to 1.0.2n.");

  script_xref(name: "URL" , value: "https://www.openssl.org/news/secadv/20171207.txt");
  script_xref(name: "URL" , value: "http://www.securityfocus.com/bid/102103");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");

  script_family("General");

  script_dependencies("gb_openssl_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("OpenSSL/installed","Host/runs_unixoide");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("host_details.inc");
include("version_func.inc");


if(!Port = get_app_port(cpe: CPE)){
  exit(0);
}

if(!Ver = get_app_version(cpe: CPE, port: Port)){
  exit(0);
}
if (Ver =~ "^(1\.0\.2)")
{
  if(version_in_range(version: Ver, test_version: "1.0.2b", test_version2: "1.0.2m"))
  {
    report =  report_fixed_ver(installed_version: Ver, fixed_version: "1.0.2n");
    security_message(data: report, port: Port);
    exit( 0 );
  }
}

exit ( 99 );

