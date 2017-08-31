###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_oracle_webLogic_server_mult_unspecified_vuln01.nasl 6449 2017-06-28 05:33:48Z santu $
#
# Oracle WebLogic Server Multiple Unspecified Vulnerabilities -01 May16
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
CPE = "cpe:/a:bea:weblogic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807566");
  script_version("$Revision: 6449 $");
  script_cve_id("CVE-2016-0638", "CVE-2016-3416", "CVE-2016-0675", "CVE-2016-0700",
                "CVE-2016-0688", "CVE-2016-0696", "CVE-2014-4217", "CVE-2013-5855",
                "CVE-2014-2481", "CVE-2014-2480", "CVE-2014-2479", "CVE-2014-4267",
                "CVE-2014-4256", "CVE-2014-4202", "CVE-2014-4253", "CVE-2014-4242",
                "CVE-2014-4255", "CVE-2014-4254", "CVE-2014-4201", "CVE-2014-4210",
                "CVE-2014-2470");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-06-28 07:33:48 +0200 (Wed, 28 Jun 2017) $");
  script_tag(name:"creation_date", value:"2016-05-03 17:27:14 +0530 (Tue, 03 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Oracle WebLogic Server Multiple Unspecified Vulnerabilities -01 May16");

  script_tag(name: "summary" , value:"The host is running Oracle WebLogic Server
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to multiple
  unspecified vulnerabilities in Oracle Fusion Middleware.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to have an impact on confidentiality, integrity, and availability.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Oracle WebLogic Server versions 10.3.6.0,
  12.1.2.0, 12.1.3.0, 12.1.1.0, 12.2.1.0 and 10.0.2.0 are affected.");

  script_tag(name:"solution", value:"Apply updates from the below links mentioned,
  http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html,
  http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/security-advisory/cpuapr2016v3-2985753.html");
  script_xref(name : "URL" , value : "http://www.oracle.com/technetwork/topics/security/cpujul2014-1972956.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("oracle_webLogic_server_detect.nasl");
  script_mandatory_keys("OracleWebLogicServer/installed");
  script_require_ports("Services/www", 7001);
  exit(0);
}


##
#Code Starts Here
##

include("host_details.inc");
include("version_func.inc");

##Varable initialization
webVer = "";
webPort = "";
report = "";

##Get Port
if(!webPort = get_app_port(cpe:CPE)){
  exit(0);
}

##Get version
if(!webVer = get_app_version(cpe:CPE, port:webPort)){
  exit(0);
}

##Check for versions equal to 10.3.6.0, 12.1.2.0, 12.1.3.0, 12.2.1.0, 10.0.2.0
if(version_is_equal(version:webVer, test_version:"10.3.6.0")||
   version_is_equal(version:webVer, test_version:"12.1.2.0")||
   version_is_equal(version:webVer, test_version:"12.1.3.0")||
   version_is_equal(version:webVer, test_version:"12.2.1.0")||
   version_is_equal(version:webVer, test_version:"12.1.1.0")||
   version_is_equal(version:webVer, test_version:"10.0.2.0"))
{
  report = report_fixed_ver(installed_version:webVer, fixed_version:"Apply the appropriate patch");
  security_message(data:report, port:webPort);
  exit(0);
}
