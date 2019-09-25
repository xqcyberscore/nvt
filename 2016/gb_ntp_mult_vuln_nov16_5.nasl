##############################################################################
# OpenVAS Vulnerability Test
#
# NTP.org 'ntp' DoS Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:ntp:ntp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106409");
  script_version("2019-09-24T10:41:39+0000");
  script_cve_id("CVE-2016-7426");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2016-06-03 11:18:33 +0700 (Fri, 03 Jun 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("NTP.org 'ntpd' DoS Vulnerability - Nov16");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/633847");

  script_tag(name:"summary", value:"NTP.org's reference implementation of NTP server, ntpd, is prone to a
  denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When ntpd is configured with rate limiting for all associations (restrict
  default limited in ntp.conf), the limits are applied also to responses received from its configured sources. An
  attacker who knows the sources (e.g., from an IPv4 refid in server response) and knows the system is
  (mis)configured in this way can periodically send packets with spoofed source address to keep the rate limiting
  activated and prevent ntpd from accepting valid responses from its sources.");

  script_tag(name:"impact", value:"A remote attacker may be able to perform a denial of service on ntpd.");

  script_tag(name:"affected", value:"Version 4.2.5p203 up to 4.2.8p8, 4.3.0 up to 4.3.93.");

  script_tag(name:"solution", value:"Upgrade to NTP.org's ntpd version 4.2.8p9, 4.3.94 or later.");

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

if((revcomp(a:version, b:"4.2.5p203") >= 0) && (revcomp(a:version, b:"4.2.8p9") < 0)) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.2.8p9", install_path:location);
  security_message(port:port, data:report, proto:proto);
  exit(0);
}

if((revcomp(a:version, b:"4.3.0") >= 0) && (revcomp(a:version, b:"4.3.94") < 0)) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.3.94", install_path:location);
  security_message(port:port, data:report, proto:proto);
  exit(0);
}

exit(99);
