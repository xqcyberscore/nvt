###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_incor_doc_cgi_search_algo_vuln_lin.nasl 8745 2018-02-09 14:30:40Z santu $
#
# Apache Tomcat Incorrectly documented CGI search algorithm Vulnerability (Linux)
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812695");
  script_version("$Revision: 8745 $");
  script_cve_id("CVE-2017-15706");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-02-09 15:30:40 +0100 (Fri, 09 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-06 12:00:53 +0530 (Tue, 06 Feb 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Tomcat Incorrectly documented CGI search algorithm Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to incorrectly documented CGI search algorithm vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists as the description of the
  search algorithm used by the CGI Servlet to identify which script to execute
  was not correct.");

  script_tag(name:"impact", value:"Successfully exploiting this issue will result
  some scripts failing to execute as expected and other scripts to execute
  unexpectedly.

  Impact Level: Application");

  script_tag(name:"affected", value:"
  Apache Tomcat versions 9.0.0.M22 to 9.0.1
  Apache Tomcat versions 8.5.16 to 8.5.23
  Apache Tomcat versions 8.0.45 to 8.0.47
  Apache Tomcat versions 7.0.79 to 7.0.82 on Linux.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 9.0.2,
  8.5.24, 8.0.48, 7.0.84 or later. For updates refer to
  http://tomcat.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/e1ef853fc0079cdb55befbd2dac042934e49288b476d5f6a649e5da2@<announce.tomcat.apache.org>");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheTomcat/installed","Host/runs_unixoide");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

tomPort = "";
appVer = "";

if(!tomPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:tomPort, exit_no_version:TRUE);
appVer = infos['version'];
path = infos['location'];

if(appVer =~ "8\.5")
{
  if(version_in_range(version:appVer, test_version: "8.5.16", test_version2: "8.5.23")){
    fix = "8.5.24";
  }
} else if(appVer =~ "7\.0")
{
  if(version_in_range(version:appVer, test_version: "7.0.79", test_version2: "7.0.82")){
    fix = "7.0.84";
  }
} else if(appVer =~ "8\.0")
{
  if(version_in_range(version:appVer, test_version: "8.0.45", test_version2: "8.0.47")){
    fix = "8.0.48";
  }
} else if(appVer =~ "9\.0")
{
  if((revcomp(a:appVer, b: "9.0.0.M22") >= 0) && (revcomp(a:appVer, b: "9.0.2") < 0)){
    fix = "9.0.2";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(port:tomPort, data: report);
  exit(0);
}
exit(0);
