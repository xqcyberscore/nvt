###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudbees_jenkins_mult_vuln02_june16_win.nasl 5083 2017-01-24 11:21:46Z cfi $
#
# CloudBees Jenkins Multiple Vulnerabilities-02-June16 (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:cloudbees:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807344");
  script_version("$Revision: 5083 $");
  script_cve_id("CVE-2015-1812 ", "CVE-2015-1813", "CVE-2015-1814");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-24 12:21:46 +0100 (Tue, 24 Jan 2017) $");
  script_tag(name:"creation_date", value:"2016-06-22 14:22:34 +0530 (Wed, 22 Jun 2016)");
  script_name("CloudBees Jenkins Multiple Vulnerabilities-02-June16 (Windows)");

  script_tag(name:"summary", value:"This host is installed with CloudBees
  Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - The part of Jenkins that issues a new API token was not adequately protected
    against anonymous attackers. This allows an attacker to escalate privileges
    on Jenkins .
  - A without any access to Jenkins can navigate the user to a carefully crafted
    URL and have the user execute unintended actions. This vulnerability can be
    used to attack Jenkins inside firewalls from outside so long as the location
    of Jenkins is known to the attacker.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive informaion, bypass the protection mechanism,
  gain elevated privileges, bypass intended access restrictions and execute
  arbitrary code.

  Impact Level: Application");

  script_tag(name:"affected", value:"CloudBees Jenkins LTS before 1.596.2 on Windows");

  script_tag(name:"solution", value:"Upgrade to CloudBees Jenkins LTS 1.596.2 or
  later. For more updates refer to https://www.cloudbees.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=1205616");
  script_xref(name : "URL" , value : "https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2015-03-23");

  script_summary("Check for the vulnerable version of CloudBees Jenkins on Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
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

if(host_runs("Windows") != "yes"){
  exit(0);
}

## Get HTTP Port
if(!jenkinPort = get_app_port(cpe:CPE)){
  exit(0);
}

# Get Version
if(!jenkinVer = get_app_version(cpe:CPE, port:jenkinPort)){
  exit(0);
}

if(version_is_less(version:jenkinVer, test_version:"1.596.2"))
{
  report = report_fixed_ver(installed_version:jenkinVer, fixed_version:"1.596.2");
  security_message(data:report);
  exit(0);
}
