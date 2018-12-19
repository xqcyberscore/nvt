###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_logitech_options_rce_vuln.nasl 12823 2018-12-18 13:47:35Z asteins $
#
# Logitech Options <= 7.0.564 Remote Command Execution Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112467");
  script_version("$Revision: 12823 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-18 14:47:35 +0100 (Tue, 18 Dec 2018) $");
  script_tag(name:"creation_date", value:"2018-12-18 14:34:12 +0100 (Tue, 18 Dec 2018)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"NoneAvailable");
  script_name("Logitech Options <= 7.0.564 Remote Command Execution Vulnerability (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_logitech_options_detect_win.nasl");
  script_mandatory_keys("logitech/options/win/detected");

  script_tag(name:"summary", value:"Logitech Options is prone to a remote command execution vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Upon installation of Logitech Options a WebSocket server is being opened
  that any website can connect to, without any origin checking at all.

  The only way of 'authentication' is by providing a pid (process ID) of a process owned by the current user.
  However, since there is no limitation of guesses, an attacker might be able to bypass this authentication in microseconds.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to send commands and options,
  configure the 'crown' to send arbitrary keystrokes to directly affect and manipulate the target system
  and have other unspecified impact on it.");
  script_tag(name:"affected", value:"Logitech Options through version 7.0.564.");
  script_tag(name:"solution", value:"No known solution is available as of 18th December, 2018.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://bugs.chromium.org/p/project-zero/issues/detail?id=1663");

  exit(0);
}

CPE = "cpe:/a:logitech:options";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) {
  exit (0);
}

vers = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:vers, test_version:"7.0.564")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"None", install_path:path);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
