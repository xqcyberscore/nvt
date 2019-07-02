###############################################################################
# OpenVAS Vulnerability Test
#
# WS FTP server multiple flaws
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
  script_oid("1.3.6.1.4.1.25623.1.0.14598");
  script_version("2019-06-26T08:42:42+0000");
  script_tag(name:"last_modification", value:"2019-06-26 08:42:42 +0000 (Wed, 26 Jun 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2004-1848", "CVE-2004-1883", "CVE-2004-1884", "CVE-2004-1885", "CVE-2004-1886");
  script_bugtraq_id(9953);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_name("WS FTP server multiple flaws");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("FTP");
  script_dependencies("secpod_wsftp_win_detect.nasl");
  script_mandatory_keys("ipswitch/ws_ftp_server/detected");

  script_tag(name:"summary", value:"According to its version number, the remote WS_FTP server is vulnerable to
  multiple flaws.

  - A buffer overflow, caused by a vulnerability in the ALLO handler, an attacker can then execute arbitrary code

  - A flaw which allow an attacker to gain elevated privileges (SYSTEM level privileges)

  - A local or remote attacker, with write privileges on a directory can create a specially crafted file
  containing a large REST argument and resulting to a denial of service.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Upgrade to the latest version of this software.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^[0-3]\.|4\.0[^0-9]|4\.0\.[12][^0-9]") {
  report = report_fixed_ver(installed_version: version, fixed_version: "See advisory");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
