###############################################################################
# OpenVAS Vulnerability Test
#
# NTP Multiple Vulnerabilities - Jan 2017
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809779");
  script_version("2019-09-24T10:41:39+0000");
  script_cve_id("CVE-2014-9296", "CVE-2014-9295");
  script_bugtraq_id(71758, 71761);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2017-01-16 17:05:06 +0530 (Mon, 16 Jan 2017)");
  script_name("NTP.org 'ntpd' Multiple Vulnerabilities - Jan17");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/852879");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2668");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2667");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2669");
  script_xref(name:"URL", value:"http://bugs.ntp.org/show_bug.cgi?id=2670");

  script_tag(name:"summary", value:"The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - An error in the 'receive' function in ntp_proto.c script within application
  which continues to execute even after detecting a certain authentication error.

  - Multiple errors in ntpd functions 'crypto_recv' (when using autokey
  authentication), 'ctl_putdata', and 'configure'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code and other unspecified effect on the affected
  system.");

  script_tag(name:"affected", value:"NTP.org's ntpd versions before 4.2.8.");

  script_tag(name:"solution", value:"Upgrade to NTP.org's ntpd version 4.2.8 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port))
  exit(0);

if(!version = infos["version"])
  exit(0);

location = infos["location"];
proto = infos["proto"];

if(version_is_less(version:version, test_version:"4.2.8")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.2.8", install_path:location);
  security_message(port:port, proto:proto, data:report);
  exit(0);
}

exit(99);
