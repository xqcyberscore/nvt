###############################################################################
# OpenVAS Vulnerability Test
#
# NTP Multiple Denial-of-Service Vulnerabilities -Mar17
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
  script_oid("1.3.6.1.4.1.25623.1.0.810678");
  script_version("2019-09-24T10:41:39+0000");
  script_cve_id("CVE-2017-6464", "CVE-2017-6462", "CVE-2017-6463", "CVE-2017-6455",
                "CVE-2017-6452", "CVE-2017-6459", "CVE-2017-6458", "CVE-2017-6451",
                "CVE-2017-6460", "CVE-2016-9042");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2017-03-23 11:35:22 +0530 (Thu, 23 Mar 2017)");
  script_name("NTP.org 'ntpd' Multiple Denial-of-Service Vulnerabilities - Mar17");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3389");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3388");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3387");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3386");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3385");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3384");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3383");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3382");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3381");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3380");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3379");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3378");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3377");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3376");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3361");

  script_tag(name:"summary", value:"The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to

  - Improper handling of a malformed mode configuration directive.

  - A buffer overflow error in Legacy Datum Programmable Time Server refclock
  driver.

  - Improper handling of an invalid setting via the :config directive.

  - Incorrect pointer usage in the function 'ntpq_stripquotes'.

  - No allocation of memory for a specific amount of items of the same size in
  'oreallocarray' function.

  - ntpd configured to use the PPSAPI under Windows.

  - Limited passed application path size under Windows.

  - An error leading to garbage registry creation in Windows.

  - Copious amounts of Unused Code.

  - Off-by-one error in Oncore GPS Receiver.

  - Potential Overflows in 'ctl_put' functions.

  - Improper use of 'snprintf' function in mx4200_send function.

  - Buffer Overflow in ntpq when fetching reslist from a malicious ntpd.

  - Potential Overflows in 'ctl_put' functions.

  - Potential denial of service in origin timestamp check functionality of ntpd.");

  script_tag(name:"impact", value:"Successful exploitation will allows remote
  attackers to conduct denial of service condition.");

  script_tag(name:"affected", value:"NTP.org's ntpd versions 4.x before 4.2.8p10 and 4.3.x
  before 4.3.94.");

  script_tag(name:"solution", value:"Upgrade to NTP.org's ntpd version 4.2.8p10 or 4.3.94
  or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

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
  if(revcomp(a:version, b:"4.2.8p10") < 0) {
    report = report_fixed_ver(installed_version:version, fixed_version:"4.2.8p10", install_path:location);
    security_message(port:port, proto:proto, data:report);
    exit(0);
  }
}

else if(version =~ "^4\.3") {
  if(revcomp(a:version, b:"4.3.94") < 0) {
    report = report_fixed_ver(installed_version:version, fixed_version:"4.3.94", install_path:location);
    security_message(port:port, proto:proto, data:report);
    exit(0);
  }
}

exit(99);
