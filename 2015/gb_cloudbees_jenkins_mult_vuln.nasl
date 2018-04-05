###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudbees_jenkins_mult_vuln.nasl 9301 2018-04-04 12:02:46Z cfischer $
#
# CloudBees Jenkins Multiple Vulnerabilities
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:cloudbees:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807001");
  script_version("$Revision: 9301 $");
  script_cve_id("CVE-2015-5317", "CVE-2015-5318", "CVE-2015-5319", "CVE-2015-5320",
                "CVE-2015-5321", "CVE-2015-5322", "CVE-2015-5323", "CVE-2015-5324",
                "CVE-2015-5325", "CVE-2015-5326", "CVE-2015-8103", "CVE-2015-7536",
                "CVE-2015-7537", "CVE-2015-7538", "CVE-2015-7539");
  script_bugtraq_id(77572, 77570, 77574, 77636, 77619);
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-04-04 14:02:46 +0200 (Wed, 04 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-12-15 17:52:00 +0530 (Tue, 15 Dec 2015)");
  script_name("CloudBees Jenkins Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with CloudBees
  Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - An error in 'Fingerprints' pages.
  - The usage of publicly accessible salt to generate CSRF protection tokens.
  - The XML external entity (XXE) vulnerability in the create-job CLI command.
  - An improper verification of the shared secret used in JNLP slave
    connections.
  - An error in sidepanel widgets in the CLI command overview and help
    pages.
  - The directory traversal vulnerability in while requesting jnlpJars.
  - An Improper restriction on access to API tokens.
  - The cross-site scripting vulnerability in the slave overview page.
  - The unsafe deserialization in Jenkins remoting.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute
  arbitrary code.

  Impact Level: Application");

  script_tag(name:"affected", value:"CloudBees Jenkins LTS before 1.625.2
  on Windows");

  script_tag(name:"solution", value:"Upgrade to CloudBees Jenkins LTS 1.625.2 or
  later. For more updates refer to https://www.cloudbees.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2015-11-11");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/installed","Host/runs_windows");
  script_require_ports("Services/www", 8080);
  exit(0);
}


## Code starts from here

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
jenkinPort = "";
jenkinVer= "";

## Get HTTP Port
if(!jenkinPort = get_app_port(cpe:CPE)){
  exit(0);
}

# Get Version
if(!jenkinVer = get_app_version(cpe:CPE, port:jenkinPort)){
  exit(0);
}

## Check for vulnerable version
if(version_is_less(version:jenkinVer, test_version:"1.625.2"))
{
  report = report_fixed_ver(installed_version:jenkinVer, fixed_version:"1.625.2");
  security_message(data:report, port:jenkinPort);
  exit(0);
}
