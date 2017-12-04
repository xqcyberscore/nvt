###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipswitch_ws_ftp_bof_vuln_win.nasl 7968 2017-12-01 08:26:28Z asteins $
#
# Ipswitch WS_FTP Professional Local Buffer Overflow Vulnerability 
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

CPE = "cpe:/a:ipswitch:ws_ftp";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812071");
  script_version("$Revision: 7968 $");
  script_cve_id("CVE-2017-16513");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 09:26:28 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-09 14:14:47 +0530 (Thu, 09 Nov 2017)");
  script_name("Ipswitch WS_FTP Professional Local Buffer Overflow Vulnerability");

  script_tag(name: "summary" , value:"This host is installed with Ipswitch WS_FTP
  Professional and is prone to local buffer overflow vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw exists due to error in the
  application where some fields (local search and backup locations) allows
  users to input data and are not properly sanitized.");

  script_tag(name: "impact" , value: "Successful exploitation will allow
  local attackers to conduct buffer overflow attacks on the affected system.

  Impact Level: Application");

  script_tag(name: "affected" , value:"Ipswitch WS_FTP Professional prior to
  version 12.6.0.3");

  script_tag(name: "solution" , value:"Upgrade to Ipswitch WS_FTP Professional
  version 12.6.0.3 or later. For updates refer to https://www.ipswitch.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name: "URL" , value : "https://www.exploit-db.com/exploits/43115");
  script_xref(name: "URL" , value : "https://docs.ipswitch.com/WS_FTP126/ReleaseNotes/English/index.htm");

  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("secpod_ws_ftp_client_detect.nasl");
  script_mandatory_keys("Ipswitch/WS_FTP_Pro/Client/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

ftpVer= "";
infos = "";
ftpPath = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
ftpVer = infos['version'];
ftpPath = infos['location'];

if(version_is_less(version:ftpVer, test_version:"12.6.0.3"))
{
  report = report_fixed_ver(installed_version:ftpVer, fixed_version:"12.6.0.3", install_path:ftpPath);
  security_message(data:report);
  exit(0);
}
exit(0);
