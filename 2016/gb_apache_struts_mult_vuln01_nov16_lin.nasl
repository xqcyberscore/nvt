###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_mult_vuln01_nov16_lin.nasl 60709 2016-11-18 14:43:17 +0530 Nov$
#
# Apache Struts Multiple Vulnerabilities-01 Nov16 (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
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

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809478");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-1181", "CVE-2016-1182", "CVE-2015-0899");
  script_bugtraq_id(91068, 91067, 74423);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-11-18 14:46:45 +0530 (Fri, 18 Nov 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Struts Multiple Vulnerabilities-01 Nov16 (Linux)");

  script_tag(name:"summary", value:"This host is running Apache Struts and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,
  - An 'actionServlet.java' script mishandles multithreaded access to an
    ActionForm instance.
  - An 'actionServlet.java' script does not properly restrict the Validator
    configuration.
  - An error in the MultiPageValidator implementation.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to execute arbitrary code or cause a denial of service or conduct
  cross-site scripting or bypass intended access restrictions.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache Struts Version 1.0 through 1.3.10
  on Linux.");

  script_tag(name:"solution", value:"There is no fix for the vulnerability and
  there never will be one. This is often the case when a product has been
  orphaned, end-of-lifed, or otherwise deprecated. Information should contain
  details about why there will be no fix issued.
  For updates refer to http://struts.apache.org");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN03188560/index.html");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN65044642/index.html");
  script_xref(name : "URL" , value : "http://jvn.jp/en/jp/JVN86448949/index.html");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ApacheStruts/installed", "Host/runs_unixoide");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
appVer = "";
appPort = "";

## Get Port
if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get version
if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

## Vulnerable version according to Advisory
## Check the vulnerable version
if(appVer =~ "^(1\.)")
{
  if(version_in_range(version:appVer, test_version:"1.0", test_version2:"1.3.10"))
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:"WillNotFix");
    security_message(data:report, port:appPort);
    exit(0);
  }
}
