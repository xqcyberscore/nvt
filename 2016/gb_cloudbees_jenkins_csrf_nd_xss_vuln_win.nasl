###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins CSRF And XSS Vulnerabilities (Windows)
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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807349");
  script_version("2019-10-17T11:27:19+0000");
  script_cve_id("CVE-2013-2034", "CVE-2013-2033", "CVE-2013-1808");
  script_bugtraq_id(59631, 59634, 58257);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-10-17 11:27:19 +0000 (Thu, 17 Oct 2019)");
  script_tag(name:"creation_date", value:"2016-07-14 13:00:47 +0530 (Thu, 14 Jul 2016)");

  script_name("Jenkins CSRF And XSS Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is installed with Jenkins and is
  prone to cross-site request forgery and cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - A cross-site request forgery (CSRF) flaw in the Jenkins master, where an
    anonymous attacker can trick an administrator to execute arbitrary code on
    Jenkins master by having him open a specifically crafted attack URL.

  - The multiple input validation errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on Jenkins master by having him open a
  specifically crafted attack URL and to execute JavaScript in the browser of other users.");

  script_tag(name:"affected", value:"Jenkins main line prior to 1.514, Jenkins LTS prior to 1.509.1.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.514,
  Jenkins LTS users should update to 1.509.1.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2013-05-02/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit(0);

if( ! infos = get_app_full( cpe:CPE, port:port ) )
  exit(0);

if( ! version = infos["version"])
  exit(0);

location = infos["location"];
proto = infos["proto"];

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if( version_is_less( version:version, test_version:"1.509.1" ) ) {
    vuln = TRUE;
    fix = "1.509.1";
  }
} else {
  if( version_is_less( version:version, test_version:"1.514" ) ) {
    vuln = TRUE;
    fix = "1.514";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
