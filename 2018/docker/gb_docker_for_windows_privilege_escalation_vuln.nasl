# Copyright (C) 2018 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107338");
  script_version("2019-06-17T14:16:12+0000");
  script_cve_id("CVE-2018-15514");
  script_tag(name:"last_modification", value:"2019-06-17 14:16:12 +0000 (Mon, 17 Jun 2019)");
  script_tag(name:"creation_date", value:"2018-09-06 14:43:30 +0200 (Thu, 06 Sep 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Docker for Windows Privilege Escalation Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_docker_for_windows_detect.nasl");
  script_mandatory_keys("docker/docker_for_windows/detected", "docker/docker_for_windows/build");
  script_tag(name:"summary", value:"Docker for Windows is prone to a Privilege Escalation Vulnerability.");
  script_tag(name:"vuldetect", value:"The script checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"HandleRequestAsync in Docker for Windows before 18.06.0-ce-rc3-win68 (edge) and before 18.06.0-ce-win72 (stable) deserialized requests over the '\\.\pipe\dockerBackend' named pipe without verifying the validity of the deserialized .NET objects. This would allow a malicious user in the 'docker-users' group (who may not otherwise have administrator access) to escalate to administrator privileges.");
  script_tag(name:"affected", value:"Docker for Windows before 18.06.0-ce-rc3-win68 (edge) and before 18.06.0-ce-win72 (stable).");
  script_tag(name:"solution", value:"Upgrade to Docker for Windows Version 18.06.0-ce-rc3-win68 (edge) respectively 18.06.0-ce-win72 (stable) or later.");
  script_xref(name:"URL", value:"https://srcincite.io/blog/2018/08/31/you-cant-contain-me-analyzing-and-exploiting-an-elevation-of-privilege-in-docker-for-windows.html");
  exit(0);
}

CPE = "cpe:/a:docker:docker_for_windows";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location ( cpe:CPE, exit_no_version:TRUE ) )
  exit ( 0 );

vers = infos ['version'];
path = infos ['location'];

build = get_kb_item( "docker/docker_for_windows/build");

# "Stable" Version Example: 18.06.0-ce-win72
if( build =~ "stable" ) {

  if( version_is_less( version:vers, test_version:"18.06.0-ce-win72" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"18.06.0-ce-win72",
    install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
  }
}

# "Edge" Version Example: 18.06.0-ce-rc3-win68
if( build =~ "edge" ) {
  if( version_is_less( version:vers, test_version:"18.06.0-ce-rc3-win68" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"18.06.0-ce-rc3-win68",
    install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
  }
}
exit( 99 );
