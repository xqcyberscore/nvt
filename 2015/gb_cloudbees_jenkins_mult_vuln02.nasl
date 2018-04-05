###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cloudbees_jenkins_mult_vuln02.nasl 9301 2018-04-04 12:02:46Z cfischer $
#
# CloudBees Jenkins Multiple Vulnerabilities -02 December15
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
  script_oid("1.3.6.1.4.1.25623.1.0.807013");
  script_version("$Revision: 9301 $");
  script_cve_id("CVE-2014-3680", "CVE-2014-3667", "CVE-2014-3666", "CVE-2014-3663",
                "CVE-2014-3662", "CVE-2014-3661");
  script_bugtraq_id(77953, 77963, 88193, 77977, 77955, 77961);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-04 14:02:46 +0200 (Wed, 04 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-12-21 15:34:06 +0530 (Mon, 21 Dec 2015)");
  script_name("CloudBees Jenkins Multiple Vulnerabilities -02 December15");

  script_tag(name:"summary", value:"This host is installed with CloudBees
  Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,
  - CloudBees Jenkins does not properly prevent downloading of plugins.
  - Insufficient sanitization of packets over the CLI channel.
  - Password exposure in DOM.
  - Error in job configuration permission.
  - Thread exhaustion via vectors related to a CLI handshake.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, to bypass bypass intended access
  restrictions and execute arbitrary code.

  Impact Level: Application");

  script_tag(name:"affected", value:"CloudBees Jenkins LTS before 1.565.3
  on Windows");

  script_tag(name:"solution", value:"Upgrade to CloudBees Jenkins LTS 1.565.3
  or later. For more updates refer to https://www.cloudbees.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");
  script_xref(name : "URL" , value : "https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2014-10-01");

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

if(version_is_less(version:jenkinVer, test_version:"1.565.3"))
{
  report = report_fixed_ver(installed_version:jenkinVer, fixed_version:"1.565.3");
  security_message(data:report, port:jenkinPort);
  exit(0);
}
