# Copyright (C) 2019 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108560");
  script_version("2019-03-20T18:49:53+0000");
  script_tag(name:"last_modification", value:"2019-03-20 18:49:53 +0000 (Wed, 20 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-03-16 08:57:17 +0100 (Sat, 16 Mar 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Report outdated Scan Engine / Environment (local)");
  script_category(ACT_SETTINGS);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");

  script_tag(name:"summary", value:"This script checks and reports an outdated scan engine for the following environments:

  - Greenbone Source Edition (GSE)

  - Greenbone Community Edition (GCE)

  used for this scan.

  NOTE: While this is not, in and of itself, a security vulnerability, a severity is reported to make you aware
  of a possible decreased scan coverage due to e.g.:

  - missing functionalities

  - missing bugfixes

  - incompatibilities within the feed.");

  script_tag(name:"solution", value:"Update to the latest available stable release for your scan environment. Please check the
  references for more information. If you're using packages provided by your Linux distribution please contact the maintainer
  of the used distribution/repository and request updated packages.

  If you want to accept the risk of a possible decreased scan coverage you can set a global override for this script as
  described in the linked manual.");

  script_xref(name:"URL", value:"https://www.greenbone.net/en/install_use_gce/");
  script_xref(name:"URL", value:"https://community.greenbone.net/t/gvm-9-stable-initial-release-2017-03-07/211");
  script_xref(name:"URL", value:"https://github.com/greenbone/");
  script_xref(name:"URL", value:"https://docs.greenbone.net/GSM-Manual/gos-4/en/vulnerabilitymanagement.html#creating-an-override");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("misc_func.inc");

expected_gce_ver  = "4.2.24";
expected_libs_ver = "9.0.3";

if( gos_vers = get_local_gos_version() ) {
  if( version_is_less( version:gos_vers, test_version:expected_gce_ver ) ) {
    report  = "Installed GCE version:        " + gos_vers + '\n';
    report += "Latest available GCE version: " + expected_gce_ver + '\n';
    report += "Reference URL:                https://www.greenbone.net/en/install_use_gce/";
    security_message( port:0, data:report );
  }
} else if( OPENVAS_VERSION && version_is_less( version:OPENVAS_VERSION, test_version:expected_libs_ver ) ) {
  report  = "Installed GVM version:        " + OPENVAS_VERSION + '\n';
  report += "Latest available GVM version: " + expected_libs_ver + '\n';
  report += "Reference URL:                https://community.greenbone.net/t/gvm-9-stable-initial-release-2017-03-07/211";
  security_message( port:0, data:report );
}

exit( 0 );
