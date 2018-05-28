###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_cache_timing_info_disc_vuln_lin.nasl 9974 2018-05-28 03:25:02Z ckuersteiner $
#
# OpenSSL Cache Timing Side Channel Attack Information Disclosure Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813154");
  script_version("$Revision: 9974 $");
  script_cve_id("CVE-2018-0737");
  script_bugtraq_id(103766);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-05-28 05:25:02 +0200 (Mon, 28 May 2018) $");
  script_tag(name:"creation_date", value:"2018-04-23 18:50:10 +0530 (Mon, 23 Apr 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("OpenSSL Cache Timing Side Channel Attack Information Disclosure Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running OpenSSL and is prone
  to cache timing side channel attack information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an error during the RSA
  key generation process which can lead to cache timing attacks.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to recover the private key which may aid in further attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"OpenSSL all versions prior to 1.1.0i and OpenSSL
  1.0.2x prior to 1.0.2p");

  script_tag(name:"solution", value:"Upgrade to OpenSSL version 1.1.0i or 1.0.2p or
  later. For updates refer to Reference links.");
  
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.openssl.org/news/secadv/20180416.txt");
  script_xref(name : "URL" , value : "http://seclists.org/oss-sec/2018/q2/50");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_openssl_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("OpenSSL/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!sslPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location( cpe:CPE, port:sslPort, exit_no_version:TRUE );
sslVer = infos['version'];
sslPath = infos['location'];

if(sslVer =~ "^(1\.0\.2)" && version_is_less(version:sslVer, test_version:"1.0.2p"))
{
  report = report_fixed_ver(installed_version:sslVer, fixed_version:"1.0.2p");
  security_message(data:report, port:sslPort);
  exit(0);
} else if(version_is_less(version:sslVer, test_version:"1.1.0i"))
{
  report = report_fixed_ver(installed_version:sslVer, fixed_version:"1.1.0i");
  security_message(data:report, port:sslPort);
  exit(0);
}
exit(0);  
