###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins CLI Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806621");
  script_version("2019-07-30T03:00:13+0000");
  script_cve_id("CVE-2015-5318", "CVE-2015-5319", "CVE-2015-5320", "CVE-2015-5324",
                "CVE-2015-5321", "CVE-2015-5322", "CVE-2015-5323", "CVE-2015-5325",
                "CVE-2015-5326");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-30 03:00:13 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"creation_date", value:"2015-11-17 12:48:36 +0530 (Tue, 17 Nov 2015)");
  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Jenkins CLI Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The host is installed with Jenkins and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist as,

  - Jenkins UI allows users to see the names of jobs and builds otherwise
    inaccessible to them on the 'Fingerprints' pages.

  - The salt used to generate the CSRF protection tokens is a publicly accessible
    value.

  - When creating a job using the create-job CLI command, external entities are
    not discarded (nor processed).

  - JNLP slave connections did not verify that the correct secret was supplied.

  - The /queue/api URL could return information about items not accessible to
    the current user.

  - The CLI command overview and help pages in Jenkins were accessible without
    Overall/Read permission.

  - Access to the /jnlpJars/ URL was not limited to the specific JAR files users
    needed to access, allowing browsing directories and downloading other files in
    the Jenkins servlet resources.

  - API tokens of other users were exposed to admins by default.

  - Slaves connecting via JNLP were not subject to the optional slave-to-master
    access control.

  - Users with the permission to take slave nodes offline can enter arbitrary
    HTML.

  - An error due to unsafe deserialization.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to gain access to sensitive information, conduct XXE, XSS and CSRF
  attacks, and execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"All Jenkins main line releases up to and including 1.637
  All Jenkins LTS releases up to and including 1.625.1.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.638
  Jenkins LTS users should update to 1.625.2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://wiki.jenkins-ci.org/display/SECURITY/Jenkins+Security+Advisory+2015-11-11");
  script_xref(name:"URL", value:"https://jenkins-ci.org/content/mitigating-unauthenticated-remote-code-execution-0-day-jenkins-cli");
  script_xref(name:"URL", value:"http://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl");
  script_mandatory_keys("jenkins/detected");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port))
  exit(0);

if (!version = infos["version"])
  exit(0);

location = infos["location"];
proto = infos["proto"];

##And Jenkins LTS users should update to 1.625.2
##For main line releases: http://mirrors.jenkins-ci.org/war
##For LTS releases: http://mirrors.jenkins-ci.org/war-stable
if(version =~ "^1.[0-9][0-9][0-9].([0-9]+)") {
  if(version_is_less(version:version, test_version:"1.625.2")) {
    fix = "For Jenkins LTS update to 1.625.2 and for Jenkins main line update to 1.638";
    VULN = TRUE;
  }
}
else if(version =~ "^1.([0-9][0-9]([0-9])?)$") {
  if(version_is_less(version:version, test_version:"1.638")) {
    fix = "For Jenkins main line update to 1.638";
    VULN = TRUE;
  }
}

if(VULN) {
  report = report_fixed_ver(installed_version: version, fixed_version: fix, install_path: location);
  security_message(data:report, port:port, proto:proto);
  exit(0);
}

exit(99);
