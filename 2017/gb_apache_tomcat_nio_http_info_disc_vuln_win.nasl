###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_tomcat_nio_http_info_disc_vuln_win.nasl 7571 2017-10-26 07:59:06Z cfischer $
#
# Apache Tomcat NIO HTTP connector Information Disclosure Vulnerability (Windows)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.811296");
  script_version("$Revision: 7571 $");
  script_cve_id("CVE-2016-8745");
  script_bugtraq_id(94828);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 09:59:06 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-08-11 12:49:43 +0530 (Fri, 11 Aug 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Tomcat NIO HTTP connector Information Disclosure Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apache Tomcat
  and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to error handling of the
  send file code for the NIO HTTP connector in Apache Tomcat resulting in the
  current Processor object being added to the Processor cache multiple times.
  This in turn means that the same Processor could be used for concurrent requests.
  Sharing a Processor can result in information leakage between requests including,
  not not limited to, session ID and the response body.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to gain access to potentially sensitive information.

  Impact Level: Application");

  script_tag(name:"affected", value:"
  Apache Tomcat versions 9.0.0.M1 to 9.0.0.M13,
  Apache Tomcat versions 8.5.0 to 8.5.8,
  Apache Tomcat versions 8.0.0.RC1 to 8.0.39,
  Apache Tomcat versions 7.0.0 to 7.0.73, and
  Apache Tomcat versions 6.0.16 to 6.0.48 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Apache Tomcat version 9.0.0.M15
  or 8.5.9 or 8.0.41 or 7.0.75 or 6.0.50 or later. For updates refer to
  http://tomcat.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://bz.apache.org/bugzilla/show_bug.cgi?id=60409");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-9.html#Fixed_in_Apache_Tomcat_9.0.0.M15");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.0.41");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-7.html#Fixed_in_Apache_Tomcat_7.0.75");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-8.html#Fixed_in_Apache_Tomcat_8.5.9");
  script_xref(name:"URL", value:"http://tomcat.apache.org/security-6.html#Fixed_in_Apache_Tomcat_6.0.50");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ApacheTomcat/installed","Host/runs_windows");
  script_require_ports("Services/www", 8080);
  exit(0);
}


include("host_details.inc");
include("revisions-lib.inc");
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

## Grep for vulnerable version
if(appVer =~ "^6")
{
  if((revcomp(a: appVer, b: "6.0.50") < 0) &&
     (revcomp(a: appVer, b: "6.0.16") >= 0)){
    fix = "6.0.50";
  }
}

else if(appVer =~ "^7")
{
  if(revcomp(a: appVer, b: "7.0.75") < 0){
    fix = "7.0.75";
  }
}

else if(appVer =~ "^(8\.5\.)")
{
  if(revcomp(a: appVer, b: "8.5.9") < 0){
    fix = "8.5.9";
  }
}

else if(appVer =~ "^(8\.)")
{
  if(revcomp(a: appVer, b: "8.0.41") < 0){
    fix = "8.0.41";
  }
}

else if(appVer =~ "^(9\.)")
{
  if(revcomp(a: appVer, b: "9.0.0.M15") < 0){
    fix = "9.0.0.M15";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(data:report, port:tomPort);
  exit(0);
}
exit(0);
