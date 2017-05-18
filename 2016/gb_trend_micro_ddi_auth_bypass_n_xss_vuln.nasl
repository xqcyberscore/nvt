###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trend_micro_ddi_auth_bypass_n_xss_vuln.nasl 5759 2017-03-29 09:01:08Z teissa $
#
# Trend Micro Deep Discovery Inspector Authentication Bypass and XSS Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:trend_micro:deep_discovery_inspector";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807355");
  script_version("$Revision: 5759 $");
  script_cve_id("CVE-2015-2873", "CVE-2015-2872");
  script_bugtraq_id(76396, 76397);
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-03-29 11:01:08 +0200 (Wed, 29 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-08-19 17:14:20 +0530 (Fri, 19 Aug 2016)");
  script_name("Trend Micro Deep Discovery Inspector Authentication Bypass and XSS Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Trend Micro Deep
  Discovery Inspector and is prone to authentication bypass and cross-site scripting
  vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to an,
  - Insufficient access restrictions for some sensitive files via a direct
    request to the system log URL, whitelist URL and blacklist URL.
  - Insufficient validation of crafted input passed to index.php and
    to the widget feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information and execute
  arbitrary javascript code in the context of current user.

  Impact Level: Application");

  script_tag(name:"affected", value:"Trend Micro Deep Discovery Inspector with
  software before 3.5, 3.6, 3.7 and 3.8");

  script_tag(name:"solution", value:"Install the vendor patch. 
  For updates refer to http://esupport.trendmicro.com/solution/en-US/1112206.aspx");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL" , value:"http://esupport.trendmicro.com/solution/en-US/1112206.aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_trendmicro_deep_discovery_inspector_detect.nasl");
  script_mandatory_keys("deep_discovery_inspector/installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!trendPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!trendVersion = get_app_version(cpe:CPE, port:trendPort)){
  exit(0);
}

if (version_is_equal(version:trendVersion, test_version: "3.8")) 
{
  report = report_fixed_ver(installed_version: trendVersion, fixed_version: "3.8 CP B1263 or 3.8 CP B2047");
  security_message(port: trendPort, data: report);
  exit(0);
}

if (version_is_equal(version:trendVersion, test_version: "3.7"))
{
  report = report_fixed_ver(installed_version: trendVersion, fixed_version: "3.7 CP B1248 or 3.7 CP B1228 or 3.7 CP B1227");
  security_message(port: trendPort, data: report);
  exit(0);
}

if (version_is_equal(version:trendVersion, test_version: "3.6"))
{
  report = report_fixed_ver(installed_version: trendVersion, fixed_version: "3.6 CP B1217");
  security_message(port: trendPort, data: report);
  exit(0);
}

if (version_is_equal(version:trendVersion, test_version: "3.5"))
{
  report = report_fixed_ver(installed_version: trendVersion, fixed_version: "3.5 CP B1477 or 3.5 CP B1544 or 3.5 CP B1433");
  security_message(port: trendPort, data: report);
  exit(0);
}
exit(0);
