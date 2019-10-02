# OpenVAS Vulnerability Test
# Description: vBulletin XSS(3)
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2005 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

CPE = "cpe:/a:vbulletin:vbulletin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.16280");
  script_version("2019-09-27T07:10:39+0000");
  script_tag(name:"last_modification", value:"2019-09-27 07:10:39 +0000 (Fri, 27 Sep 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"OSVDB", value:"13150");
  script_tag(name:"cvss_base", value:"2.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_name("vBulletin XSS(3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2005 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("vbulletin_detect.nasl");
  script_mandatory_keys("vbulletin/detected");

  script_tag(name:"solution", value:"Upgrade to version 2.3.6 or 3.0.6.");

  script_tag(name:"summary", value:"The remote version of vBulletin seems to be
  prior or equal to version 2.3.5 or 3.0.5. These versions are vulnerable to a
  cross-site scripting issue, due to a failure of the application to properly
  sanitize user-supplied URI input.");

  script_tag(name:"impact", value:"As a result of this vulnerability, it is possible
  for a remote attacker to create a malicious link containing script code that will
  be executed in the browser of an unsuspecting user when followed.

  This may facilitate the theft of cookie-based authentication credentials
  as well as other attacks.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"2.3.6") ||
   version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.5")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"2.3.6/3.0.6", install_path:path);
  security_message(data:report, port:port);
  exit(0);
}

exit(99);
