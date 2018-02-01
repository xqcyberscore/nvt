###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tiv_endpoint_manager_mult_vuln_oct16.nasl 8598 2018-01-31 09:59:32Z cfischer $
#
# IBM Tivoli Endpoint Manager Multiple Vulnerabilities Oct16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:ibm:tivoli_endpoint_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809368");
  script_version("$Revision: 8598 $");
  script_cve_id("CVE-2016-0292", "CVE-2016-0397");
  script_bugtraq_id(92467, 92468);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-01-31 10:59:32 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name:"creation_date", value:"2016-10-18 13:23:56 +0530 (Tue, 18 Oct 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Tivoli Endpoint Manager Multiple Vulnerabilities Oct16");

  script_tag(name: "summary" , value:"This host is installed with IBM Tivoli
  Endpoint Manager and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"Multiple flaws are due to
  - Cleartext system password is used.
  - Improper validation of incoming http traffic.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to obtain sensitive information and local users to discover the
  cleartext system password by reading a report.

  Impact Level: Application");

  script_tag(name: "affected" , value:"IBM Tivoli Endpoint Manager versions
  9.x before 9.5.2.");

  script_tag(name: "solution" , value:"Upgrade to IBM Tivoli Endpoint Manager
  version 9.5.2, or later,
  For updates refer to http://www-03.ibm.com/software/products/en/endpoint-manager-family");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21985907");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_endpoint_manager_web_detect.nasl");
  script_mandatory_keys("ibm_endpoint_manager/installed");
  script_require_ports("Services/www", 52311);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!tivPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!tivVer = get_app_version(cpe:CPE, port:tivPort)){
  exit(0);
}

##Check for Vulnerable Version
if(version_in_range(version:tivVer, test_version:"9.0", test_version2:"9.5.1"))
{
  report = report_fixed_ver(installed_version:tivVer, fixed_version:"9.5.2");
  security_message(port:tivPort, data:report);
  exit(0);
}
