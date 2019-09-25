###############################################################################
# OpenVAS Vulnerability Test
#
# NTP 'ntpd' Autokey Stack Overflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.900652");
  script_version("2019-09-24T10:41:39+0000");
  script_tag(name:"last_modification", value:"2019-09-24 10:41:39 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2009-05-22 08:49:17 +0200 (Fri, 22 May 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-1252");
  script_bugtraq_id(35017);
  script_name("NTP.org 'ntpd' Autokey Stack Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Buffer overflow");
  script_dependencies("gb_ntp_detect_lin.nasl");
  script_mandatory_keys("ntpd/version/detected");

  script_xref(name:"URL", value:"https://launchpad.net/bugs/cve/2009-1252");
  script_xref(name:"URL", value:"http://rhn.redhat.com/errata/RHSA-2009-1040.html");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=499694");

  script_tag(name:"affected", value:"NTP.org's ntpd version prior to 4.2.4p7 and
  4.2.5 to 4.2.5p73.");

  script_tag(name:"insight", value:"This flaw is due to configuration error in ntp daemon's NTPv4
  authentication code. If ntp daemon is configured to use Public Key Cryptography for NTP Packet
  authentication which lets the attacker send crafted NTP requests.");

  script_tag(name:"solution", value:"Apply the security update according to the OS version.");

  script_tag(name:"summary", value:"The host is running NTP.org's reference implementation
  of NTP server, ntpd and is prone to a stack overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker craft a specially malicious
  NTP request packet which can crash ntp daemon or can cause arbitrary code
  execution in the affected machine with local user's privilege.");

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

if((revcomp(a:version, b:"4.2.4p7") < 0) ||
   ((revcomp(a:version, b:"4.2.5") >= 0) && (revcomp(a:version, b:"4.2.5p73") <= 0)) ||
   (revcomp(a:version, b:"4.2.4p7-rc2") == 0)) {
  report = report_fixed_ver(installed_version:version, fixed_version:"4.2.4p7/4.2.5p74", install_path:location);
  security_message(port:port, proto:proto, data:report);
  exit(0);
}

exit(99);
