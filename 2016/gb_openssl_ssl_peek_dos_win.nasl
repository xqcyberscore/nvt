##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openssl_ssl_peek_dos_win.nasl 7545 2017-10-24 11:45:30Z cfischer $
# OpenSSL SSL_peek hang on empty record DoS vulnerability (Windows)
#
# Authors:
# Tameem Eissa <tameem.eissa..at..greenbone.net>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_insight = " OPENSSL suffers from the possibility of DoS attack through sending an empty record which causes SSL/TLS to hang during a call to SSL_peek().";

tag_impact = "Successful exploitation could result in service crash.";

tag_affected = "OpenSSL 1.1.0.";

tag_summary = "This host is running OpenSSL and prone to denial of service vulnerability.";

tag_solution = "OpenSSL 1.1.0 users should upgrade to 1.1.0a. ";

CPE = "cpe:/a:openssl:openssl";


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107053");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-6305", "CVE-2016-6308", "CVE-2016-6307");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"creation_date", value:"2016-09-26 06:40:16 +0200 (Mon, 26 Sep 2016)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_name("OpenSSL SSL_peek hang on empty record DoS vulnerability (Windows)");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20160922.txt");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_openssl_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("OpenSSL/installed","Host/runs_windows");
  script_require_ports("Services/www", 80);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");


## Variable Initialization
sslVer = "";

## Get Version
if(!sslVer = get_app_version(cpe:CPE))
{
  exit(0);
}

## Checking for Vulnerable version 

if(version_is_equal(version:sslVer, test_version:"1.1.0"))
{
  fix = "1.1.0a";
  VUL = TRUE;
}

if (VUL)
{
  report = report_fixed_ver(installed_version:sslVer, fixed_version:fix);
  security_message(data:report);
  exit(0);
}





