###############################################################################
# OpenVAS Vulnerability Test
#
# NTP ':config' Command Arbitrary File Overwrite Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.811253");
  script_version("2019-09-24T10:41:39+0000");
  script_cve_id("CVE-2015-7703");
  script_bugtraq_id(77278);
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2017-07-25 11:30:12 +0530 (Tue, 25 Jul 2017)");
  script_name("NTP.org 'ntpd' ':config' Command Arbitrary File Overwrite Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug2902");

  script_tag(name:"summary", value:"The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to a arbitrary file-overwrite vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper access
  restrictions for the 'pidfile' or 'driftfile' directives in NTP.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to send remote configuration requests, and if the attacker knows
  the remote configuration password, it's possible for an attacker to use
  the 'pidfile' or 'driftfile' directives to potentially overwrite other
  files.");

  script_tag(name:"affected", value:"NTP.org's ntpd versions 4.x before 4.2.8p4 and
  4.3.0 before 4.3.77.");

  script_tag(name:"solution", value:"Upgrade to NTP.org's ntpd version 4.2.8p4 or 4.3.77
  or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_full(cpe:CPE, port:port))
  exit(0);

if(!version = infos["version"])
  exit(0);

location = infos["location"];
proto = infos["proto"];

if(version =~ "^4\.[0-2]") {
  if(revcomp(a:version, b:"4.2.8p4") < 0) {
    fix = "4.2.8p4";
  }
}

else if(version =~ "^4\.3") {
  if(revcomp(a:version, b:"4.3.77") < 0) {
    fix = "4.3.77";
  }
}

if(fix) {
  report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
  security_message(port:port, proto:proto, data:report);
  exit(0);
}

exit(99);
