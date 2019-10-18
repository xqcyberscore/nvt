###############################################################################
# OpenVAS Vulnerability Test
#
# Jenkins Multiple Vulnerabilities - Feb14 (Windows)
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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807012");
  script_version("2019-10-17T11:27:19+0000");
  script_cve_id("CVE-2014-2068", "CVE-2014-2066", "CVE-2014-2065", "CVE-2014-2064",
                "CVE-2014-2063", "CVE-2014-2062", "CVE-2014-2061", "CVE-2014-2060",
                "CVE-2014-2058", "CVE-2013-7285", "CVE-2013-5573");
  script_bugtraq_id(65694, 65720);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-10-17 11:27:19 +0000 (Thu, 17 Oct 2019)");
  script_tag(name:"creation_date", value:"2015-12-21 15:34:06 +0530 (Mon, 21 Dec 2015)");

  script_name("Jenkins Multiple Vulnerabilities - Feb14 (Windows)");

  script_tag(name:"summary", value:"This host is installed with
  Jenkins and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Improper access restiction by 'BuildTrigger'.

  - Improper session handling by 'Winstone servlet container'.

  - Error in input control in PasswordParameterDefinition.

  - Error in handling of API tokens.

  - Error in 'loadUserByUsername' function in the
  hudson/security/HudsonPrivateSecurityRealm.java script.

  - Insufficient validation of user supplied input via iconSize cookie.

  - Session fixation vulnerability via vectors involving the 'override' of
    Jenkins cookies.

  - 'doIndex' function in hudson/util/RemotingDiagnostics.java script does not
    restrict accessing sensitive information via vectors related to heapDump.

  - An unspecified vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain sensitive information, hijack web sessions, conduct
  clickjacking attacks, inject arbitrary web script or HTML, bypass the
  protection mechanism, gain elevated privileges, bypass intended access
  restrictions and execute arbitrary code.");

  script_tag(name:"affected", value:"Jenkins main line prior to 1.551, Jenkins LTS prior to 1.532.2.");

  script_tag(name:"solution", value:"Jenkins main line users should update to 1.551,
  Jenkins LTS users should update to 1.532.2.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2014/02/21/2");
  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2014-02-14/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
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
  if( version_is_less( version:version, test_version:"1.532.2" ) ) {
    vuln = TRUE;
    fix = "1.532.2";
  }
} else {
  if( version_is_less( version:version, test_version:"1.551" ) ) {
    vuln = TRUE;
    fix = "1.551";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
