###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mult_vuln01_jan16.nasl 8598 2018-01-31 09:59:32Z cfischer $
#
# IBM Websphere Apllication Server Multiple Vulnerabilities-01 Jan16
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806822");
  script_version("$Revision: 8598 $");
  script_cve_id("CVE-2012-3293","CVE-2012-2190");
  script_bugtraq_id(55149, 55185);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-01-31 10:59:32 +0100 (Wed, 31 Jan 2018) $");
  script_tag(name:"creation_date", value:"2016-01-18 18:44:43 +0530 (Mon, 18 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IBM Websphere Apllication Server Multiple Vulnerabilities-01 Jan16");

  script_tag(name: "summary" , value:"This host is installed with IBM Websphere
  apllication server and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"Multiple flaws are due to,
  - An error in the Global Secure ToolKit (GSKit).
  - An improper validation of input in the Administrative Console.");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  A remote attacker to monitor and capture user activity,and also leads
  to cause denial of service.

  Impact Level: Application");

  script_tag(name: "affected" , value:"IBM WebSphere Application Server (WAS)
  6.1.x before 6.1.0.45, 7.0.x before 7.0.0.25, 8.0.x before 8.0.0.4,
  and 8.5.x before 8.5.0.1");

  script_tag(name: "solution" , value:"Upgrade to IBM WebSphere Application
  Server (WAS) version 6.1.0.45, or 7.0.0.25, or 8.0.0.4, or 8.5.0.1, or later
  For updates refer to http://www-03.ibm.com/software/products/en/appserv-was");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21606096");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21611313");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_mandatory_keys("ibm_websphere_application_server/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!wasPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!wasVer = get_app_version(cpe:CPE, port:wasPort)){
  exit(0);
}

if(version_in_range(version:wasVer, test_version:"6.1", test_version2:"6.1.0.44"))
{
  fix = "6.1.0.45";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"7.0", test_version2:"7.0.0.24"))
{
  fix = "7.0.0.25";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.0", test_version2:"8.0.0.3"))
{
  fix = "8.0.0.4";
  VULN = TRUE;
}

else if(version_in_range(version:wasVer, test_version:"8.5", test_version2:"8.5.0.0"))
{
  fix = "8.5.0.1";
  VULN = TRUE;
}

if(VULN)
{
  report = report_fixed_ver( installed_version:wasVer, fixed_version:fix );
  security_message(data:report, port:wasPort);
  exit(0);
}