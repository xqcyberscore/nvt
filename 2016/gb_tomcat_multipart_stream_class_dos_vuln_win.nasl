###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tomcat_multipart_stream_class_dos_vuln_win.nasl 60710 2016-07-13 11:25:47 +0530 July$
#
# Apache Tomcat 'MultipartStream' Class Denial of Service Vulnerability (Windows)
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

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808197");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-3092");
  script_bugtraq_id(91453);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-07-13 19:19:54 +0530 (Wed, 13 Jul 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat 'MultipartStream' Class Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with
  the help of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an error in the
  'MultipartStream' class in Apache Commons Fileupload when processing 
  multi-part requests.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to cause a denial of service (CPU consumption).

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache Tomcat 7.x before 7.0.70, 8.0.0.RC1 before 8.0.36,
  8.5.x before 8.5.3, and 9.0.0.M1 before 9.0.0.M7 on Windows");

  script_tag(name:"solution", value:"Upgrade to version 7.0.70, or 8.0.36,
  or 8.5.3, or 9.0.0.M7, or later.
  For updates refer to http://tomcat.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");
  
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheTomcat/installed","Host/runs_windows");
  script_require_ports("Services/www", 8080);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
appPort = "";
appVer = "";

## get the port
if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

if(appVer =~ "^(7|8|9)")
{
  ## Grep for vulnerable version
  if(version_in_range(version:appVer, test_version:"7.0.1", test_version2:"7.0.69"))
  {
    fix = "7.0.70";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"8.5.0", test_version2:"8.5.2"))
  {
    fix = "8.5.3";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"8.0.0.RC1", test_version2:"8.0.35"))
  {
    fix = "8.0.36";
    VULN = TRUE;
  }

  else if(version_in_range(version:appVer, test_version:"9.0.0.M1", test_version2:"9.0.0.M7"))
  {
    fix = "9.0.0.M8";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
    security_message(data:report, port:appPort);
    exit(0);
  }
}
