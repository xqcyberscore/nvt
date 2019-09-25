###############################################################################
# OpenVAS Vulnerability Test
#
# NTP Local Buffer Overflow And Sybil Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.813448");
  script_version("2019-09-24T10:41:39+0000");
  script_cve_id("CVE-2018-12327", "CVE-2016-1549");
  script_bugtraq_id(104517, 88200);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2018-06-25 17:21:15 +0530 (Mon, 25 Jun 2018)");
  script_name("NTP.org 'ntpd' Local Buffer Overflow And Sybil Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"https://gist.github.com/fakhrizulkifli/9b58ed8e0354e8deee50b0eebd1c011f");
  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/44909");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3505");
  script_xref(name:"URL", value:"http://support.ntp.org/bin/view/Main/NtpBug3012P12");
  script_xref(name:"URL", value:"http://www.ntp.org/downloads.html");

  script_tag(name:"summary", value:"The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to local buffer overflow and sybil vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - An insufficient validation of input argument for an IPv4 or IPv6
  command-line parameter.

  - If a system is set up to use a trustedkey and if one is not using the feature
  allowing an optional 4th field in the ntp.keys file to specify which IPs can serve time.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute code or escalate to higher privileges and bypass certain security
  restrictions and perform some unauthorized actions to the application.
  This may aid in further attacks.");

  script_tag(name:"affected", value:"NTP.org's ntpd versions 4.x up to, but not including
  4.2.8p12, and 4.3.0 up to, but not including 4.3.94.");

  script_tag(name:"solution", value:"Upgrade to NTP.org's ntpd version 4.2.8p12 or 4.3.94 or
  later. Please see the references for more information.");

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

if(version =~ "^4\.") {
  if(revcomp(a:version, b:"4.2.8p11") <= 0) {
    fix = "4.2.8p12";
  }
  else if(version =~ "^4\.3" && (revcomp(a:version, b:"4.3.94") < 0)) {
    fix = "4.3.94";
  }

  if(fix) {
    report = report_fixed_ver(installed_version:version, fixed_version:fix, install_path:location);
    security_message(port:port, proto:proto, data:report);
    exit(0);
  }
}

exit(99);
