###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_config_par_dir_trav_vuln_lin.nasl 70551 2016-07-24 11:25:47 +0530 April$
#
# Apache Tomcat Config Parameter Directory Traversal Vulnerability (Linux)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.810736");
  script_version("$Revision: 7676 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-07 09:01:38 +0100 (Tue, 07 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-04-10 15:51:52 +0530 (Mon, 10 Apr 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Apache Tomcat Config Parameter Directory Traversal Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running Apache Tomcat and is
  prone to directory traversa vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Apache Tomcat is affected by a directory
  traversal vulnerability. Attackers may potentially exploit this to access
  unauthorized information by supplying specially crafted strings in input
  parameters of the application.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to obtain sensitive information from requests other then their own.

  Impact Level: Application");

  ## At the moment not sure about 9, 8 and 6 branches)
  script_tag(name:"affected", value:"Apache Tomcat versions 7.0.76 on Linux.");

  script_tag(name:"solution", value:"No solution or patch is available as of
  7th November, 2017. Information regarding this issue will be updated once the
  solution details are available.
  For updates refer to http://tomcat.apache.org");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2017/Apr/24");
  script_xref(name:"URL", value:"http://www.defensecode.com/advisories/DC-2017-03-001_DefenseCode_ThunderScan_SAST_Apache_Tomcat_Security_Advisory.pdf");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheTomcat/installed","Host/runs_unixoide");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
tomPort = "";
appVer = "";

## get the port
if(!tomPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!appVer = get_app_version(cpe:CPE, port:tomPort)){
  exit(0);
}

if(version_is_equal(version:appVer, test_version:"7.0.76"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"None");
  security_message(data:report, port:tomPort);
  exit(0);
}
