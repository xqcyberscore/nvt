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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112523");
  script_version("$Revision: 14008 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 08:38:19 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2019-02-28 11:32:11 +0100 (Thu, 28 Feb 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2019-9215");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Live555 Streaming Media < 2019.02.27 Invalid Memory Access Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_live555_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("live555_streaming_media/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"Live555 Streaming Media is prone to an invalid memory access vulnerability.");
  script_tag(name:"insight", value:"The function 'parseAuthorizationHeader()' could cause a memory access error for
  some malformed headers.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to cause a Denial of Service (Segmentation fault)
  or possibly have unspecified other impact.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"Live555 Streaming Media through version 2019.02.03.");
  script_tag(name:"solution", value:"Update to version 2019.02.27.");

  script_xref(name:"URL", value:"http://www.live555.com/liveMedia/public/changelog.txt");

  exit(0);
}

CPE = "cpe:/a:live555:streaming_media";

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

if(!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if(version_is_less(version: vers, test_version: "2019.02.27")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "2019.02.27");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
