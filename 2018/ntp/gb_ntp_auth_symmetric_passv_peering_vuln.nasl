###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ntp_auth_symmetric_passv_peering_vuln.nasl 9296 2018-04-04 09:19:02Z cfischer $
#
# NTP Authenticated Symmetric Passive Peering Remote Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.812793");
  script_version("$Revision: 9296 $");
  script_cve_id("CVE-2018-7170");
  script_bugtraq_id(103194);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-04 11:19:02 +0200 (Wed, 04 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-07 12:17:55 +0530 (Wed, 07 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); ##qod is unreliable because of backort issue
  script_name("NTP Authenticated Symmetric Passive Peering Remote Vulnerability");

  script_tag(name: "summary" , value:"The host is running NTP and is prone to
  a remote security vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exist due to if a system is 
  set up to use a trustedkey and if one is not using the feature introduced in 
  ntp-4.2.8p6 allowing an optional 4th field in the ntp.keys file to specify 
  which IPs can serve time.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass certain security restrictions and perform some unauthorized
  actions to the application. This may aid in further attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"NTP version 4.2.x before 4.2.8p7 and 4.3.x before 4.3.92");

  script_tag(name:"solution", value:"Upgrade to NTP version 4.2.8p7 or 4.2.8p11
  or 4.3.92. For updates refer to http://www.ntp.org/downloads.html");

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

ntpVer = 0;
report = "";
ntpPort = "";

if(!ntpPort = get_app_port(cpe:CPE)){
 exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:ntpPort, exit_no_version:TRUE);
ntpVer = infos['version'];
path = infos['location'];

if(ntpVer =~ "^(4\.2)")
{
  if(revcomp(a: ntpVer, b: "4.2.8p7") < 0){
    fix = "4.2.8p7 or 4.2.8p11";
  }
}
else if(ntpVer =~ "^(4\.3)")
{
  if(revcomp(a: ntpVer, b: "4.3.92") < 0){
    fix = "4.3.92 or 4.2.8p11";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:ntpVer, fixed_version:fix, install_path:path);
  security_message(data:report, port:ntpPort, proto:"udp");
  exit(0);
}
exit(0);
