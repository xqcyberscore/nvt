###############################################################################
# OpenVAS Vulnerability Test
#
# WS FTP CWD DoS
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
#
# Copyright:
# Copyright (C) 2004 David Maciejak
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
  script_oid("1.3.6.1.4.1.25623.1.0.14586");
  script_version("2019-06-26T08:42:42+0000");
  script_tag(name:"last_modification", value:"2019-06-26 08:42:42 +0000 (Wed, 26 Jun 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(217);
  script_cve_id("CVE-1999-0362");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("WS FTP CWD DoS");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("secpod_wsftp_win_detect.nasl");
  script_mandatory_keys("ipswitch/ws_ftp_server/detected");

  script_tag(name:"summary", value:"According to its version number, your remote WS_FTP server is vulnerable to a
  denial of service.");

  script_tag(name:"impact", value:"A logged attacker submitting a 'CWD' command along with arbitrary characters
  will deny the ftp service.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^1\.0\.[0-2][^0-9]") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
