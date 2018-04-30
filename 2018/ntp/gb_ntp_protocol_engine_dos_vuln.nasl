###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_protocol_engine_dos_vuln.nasl 9657 2018-04-27 10:38:29Z cfischer $
#
# NTP 'protocol engine' Denial of Service Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.812792");
  script_version("$Revision: 9657 $");
  script_cve_id("CVE-2018-7185");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 12:38:29 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-07 12:09:28 +0530 (Wed, 07 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("NTP 'protocol engine' Denial of Service Vulnerability");

  script_tag(name: "summary" , value:"The host is running NTP and is prone to
  a denial of service vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name: "insight" , value:"The flaw exist due to a bug that was
  inadvertently introduced into the 'protocol engine' that allows a non-authenticated
  zero-origin (reset) packet to reset an authenticated interleaved peer association.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial-of-service condition, denying service to legitimate
  users.

  Impact Level: Application");

  script_tag(name:"affected", value:"ntp versions 4.2.6 through 4.2.8p10 before 4.2.8p11");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.8p11 or later.
  For updates refer to http://www.ntp.org/downloads.html");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "http://support.ntp.org/bin/view/Main/NtpBug3454");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("NTP/Running", "NTP/Linux/Ver");
  script_require_udp_ports(123);
  exit(0);
}

##
## Code Starts Here
##

include("version_func.inc");
include("revisions-lib.inc");
include("host_details.inc");

if(!ntpPort = get_app_port(cpe:CPE)){
 exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:ntpPort, exit_no_version:TRUE);
ntpVer = infos['version'];
path = infos['location'];

if(ntpVer =~ "^(4\.2)")
{
  if(revcomp(a: ntpVer, b: "4.2.6") >= 0 && revcomp(a: ntpVer, b: "4.2.8p11") < 0)
  {
    report = report_fixed_ver(installed_version:ntpVer, fixed_version:"4.2.8p11", install_path:path);
    security_message(data:report, port:ntpPort, proto:"udp");
    exit(0);
  }
}
exit(0);
