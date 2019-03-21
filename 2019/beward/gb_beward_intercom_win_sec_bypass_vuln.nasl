###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_beward_intercom_win_sec_bypass_vuln.nasl 13699 2019-02-15 14:29:50Z cfischer $
#
# BEWARD Intercom <= 2.3.1.34471 Security Bypass Vulnerability (Windows)
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, https://www.greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.107484");
  script_version("$Revision: 13699 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-15 15:29:50 +0100 (Fri, 15 Feb 2019) $");
  script_tag(name:"creation_date", value:"2019-01-28 11:45:50 +0100 (Mon, 28 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("BEWARD Intercom <= 2.3.1.34471 Security Bypass Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_beward_intercom_detect_win.nasl");
  script_mandatory_keys("beward/intercom/win/detected");

  script_tag(name:"summary", value:"BEWARD Intercom on Windows is prone to a security bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The application stores logs and sensitive information in an unencrypted binary file called BEWARD.INTERCOM.FDB.");
  script_tag(name:"impact", value:"A local attacker that has access to the current user session can successfully disclose
  plain-text credentials that can be used to bypass authentication to the affected IP camera and door station and bypass access control in place.");
  script_tag(name:"affected", value:"BEWARD Intercom on Windows versions through 2.3.1.34471.");
  script_tag(name:"solution", value:"No known solution is available as of 28th January, 2019.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5505.php");

  exit(0);
}

CPE = "cpe:/a:beward:intercom";

include( "host_details.inc" );
include( "version_func.inc" );

if(!version = get_app_version(cpe: CPE)) exit(0);

if(version_is_less_equal(version: version, test_version: "2.3.1.34471")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None Available");
  security_message(data: report, port: 0);
  exit(0);
}

exit(99);
