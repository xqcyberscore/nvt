###############################################################################
# OpenVAS Vulnerability Test
#
# WS FTP overflows
#
# Authors:
# Michel Arboi <arboi@alussinan.org>
#
# Copyright:
# Copyright (C) 2002 Michel Arboi
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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

CPE = "cpe:/a:ipswitch:ws_ftp_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11094");
  script_version("2019-06-26T08:42:42+0000");
  script_tag(name:"last_modification", value:"2019-06-26 08:42:42 +0000 (Wed, 26 Jun 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2001-1021");

  script_name("WS FTP overflows");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2002 Michel Arboi");
  script_family("FTP");
  script_dependencies("secpod_wsftp_win_detect.nasl");
  script_mandatory_keys("ipswitch/ws_ftp_server/detected");

  script_tag(name:"summary", value:"It was possible to shut down the remote
  FTP server by issuing a command followed by a too long argument.");

  script_tag(name:"impact", value:"An attacker may use this flow to prevent your site from
  sharing some resources with the rest of the world, or even execute arbitrary code on your system.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version your FTP server.");

  script_tag(name:"qod_type", value:"remote_probe");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^2\.0\.[0-2]") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
