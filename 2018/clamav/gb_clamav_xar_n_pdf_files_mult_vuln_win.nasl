###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clamav_xar_n_pdf_files_mult_vuln_win.nasl 9638 2018-04-27 02:43:52Z ckuersteiner $
#
# ClamAV 'PDF' and 'XAR Files Parsing Multiple Vulnerabilities (Windows)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812577");
  script_version("$Revision: 9638 $");
  script_cve_id("CVE-2018-0202", "CVE-2018-1000085");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 04:43:52 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-03-21 11:04:51 +0530 (Wed, 21 Mar 2018)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("ClamAV 'PDF' and 'XAR Files Parsing Multiple Vulnerabilities (Windows)");

  script_tag(name:"summary", value:"This host is installed with ClamAV and is
  prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to

  - An incorrectly handled parsing certain PDF files and
 
  - An incorrectly handled parsing certain XAR files.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to cause a denial of service and potentially execute arbitrary code
  on the affected device.

  Impact Level: Application");

  script_tag(name:"affected", value:"ClamAV version 0.99.3 and prior on Windows");

  script_tag(name:"solution", value:"Update to version 0.99.4 or later,
  For updates refer to https://www.clamav.net/downloads");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name : "URL" , value : "https://github.com/Cisco-Talos/clamav-devel/commit/d96a6b8bcc7439fa7e3876207aa0a8e79c8451b6");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("ClamAV/remote/Ver","Host/runs_windows");
  script_require_ports(3310);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!clamPort = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:clamPort, exit_no_version:TRUE);
clamVer = infos['version'];
path = infos['location'];

## Check for vulnerable version
if(version_is_less(version:clamVer, test_version:"0.99.4"))
{
  report = report_fixed_ver(installed_version:clamVer, fixed_version:"0.99.4", install_path:path);
  security_message(data:report, port:clamPort);
  exit(0);
}
