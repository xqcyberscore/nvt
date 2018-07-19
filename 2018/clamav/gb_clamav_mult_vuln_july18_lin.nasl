###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_mult_vuln_july18_lin.nasl 10540 2018-07-19 07:26:13Z santu $
#
# ClamAV Multiple Vulnerabilities July18 (Linux)
#
# Authors:
# Rajat Mishra <rajatm@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation;
# either version 2 of the License, or (at your option) any later version.
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

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813578");
  script_version("$Revision: 10540 $");
  script_cve_id("CVE-2018-0360", "CVE-2018-0361");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-07-19 09:26:13 +0200 (Thu, 19 Jul 2018) $");
  script_tag(name:"creation_date", value:"2018-07-17 15:54:58 +0530 (Tue, 17 Jul 2018)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ClamAV Multiple Vulnerabilities July18 (Linux)");

  script_tag(name:"summary", value:"This host is installed with ClamAV and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - A lack PDF object length check.
 
  - HWP integer overflow error in function 'parsehwp3_paragraph' in file
    libclamav/hwp.c.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause denial of service and lengthen file parsing time.

  Impact Level: Application");

  script_tag(name:"affected", value:"ClamAV version before 0.100.1 on Linux");

  script_tag(name:"solution", value:"Update to version 0.100.1 or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://blog.clamav.net/2018/07/clamav-01001-has-been-released.html");
  script_xref(name : "URL" , value : "https://secuniaresearch.flexerasoftware.com/secunia_research/2018-12/");
  script_xref(name : "URL" , value : "https://www.clamav.net/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ClamAV/remote/Ver","Host/runs_unixoide");
  script_require_ports(3310);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!clamPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!infos = get_app_version_and_location(cpe:CPE, port:clamPort, exit_no_version:TRUE)) exit(0);
clamVer = infos['version'];
path = infos['location'];

if(version_is_less(version:clamVer, test_version:"0.100.1"))
{
  report = report_fixed_ver(installed_version:clamVer, fixed_version:"0.100.1", install_path:path);
  security_message(data:report, port:clamPort);
  exit(0);
}
