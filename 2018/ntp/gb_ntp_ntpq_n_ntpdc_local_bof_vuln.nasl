###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_ntpq_n_ntpdc_local_bof_vuln.nasl 10352 2018-06-28 07:09:51Z santu $
#
# NTP 'ntpq' and 'ntpdc' Local Buffer Overflow Vulnerability
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
  script_version("$Revision: 10352 $");
  script_cve_id("CVE-2018-12327");
  script_bugtraq_id(104517);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-06-28 09:09:51 +0200 (Thu, 28 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-06-25 17:21:15 +0530 (Mon, 25 Jun 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); ##backport issue
  script_name("NTP 'ntpq' and 'ntpdc' Local Buffer Overflow Vulnerability");

  script_tag(name: "summary" , value:"The host is running NTP and is prone to
  a local buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to an insufficient
  validation of input argument for an IPv4 or IPv6 command-line parameter.");

  script_tag(name:"impact", value:"Successful exploitation will allow a local
  attacker to execute code or escalate to higher privileges.

  Impact Level: Application");

  script_tag(name:"affected", value:"NTP version 4.2.8p11 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of
  28th June, 2018. Information regarding this issue will be updated once
  solution details are available.For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_xref(name : "URL" , value : "https://gist.github.com/fakhrizulkifli/9b58ed8e0354e8deee50b0eebd1c011f");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/44909");
  script_xref(name : "URL" , value : "http://www.ntp.org/downloads.html");

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

if(revcomp(a:ntpVer, b: "4.2.8p11") <= 0)
{
  report = report_fixed_ver(installed_version:ntpVer, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report, port:ntpPort, proto:"udp");
  exit(0);
}
exit(0);
