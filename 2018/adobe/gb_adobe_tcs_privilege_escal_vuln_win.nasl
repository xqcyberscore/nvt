###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_tcs_privilege_escal_vuln_win.nasl 12064 2018-10-25 05:58:08Z santu $
#
# Adobe TCS Privilege Escalation Vulnerability (Windows)
#
# Authors:
# Vidita V Koushik <vidita@secpod.com>
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

CPE = "cpe:/a:adobe:tcs";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814313");
  script_version("$Revision: 12064 $");
  script_cve_id("CVE-2018-15976");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:S/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 07:58:08 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-10-12 10:15:17 +0530 (Fri, 12 Oct 2018)");
  script_name(" Adobe TCS Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is running Adobe TCS and is prone
  to privilege escalation vulnerability");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to insecure .dll loading
  mechanism when opening files. A local attacker can place a file along with specially
  crafted .dll file on a remote SBM or WebDAV share, trick the victim into opening it
  and execute arbitrary code on the target system with privileges of the current victim.");

  script_tag(name:"impact", value:"Successful exploitation allows a local attacker
  to gain elevated privileges and compromise the vulnerable system.");

  script_tag(name:"affected", value:"Adobe TCS versions 7.1.57 and prior.");

  script_tag(name:"solution", value:"Update to Adobe TCS 2019 Release or later.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/techcommsuite/apsb18-38.html");
  script_xref(name:"URL", value:"https://www.cybersecurity-help.cz/vdb/SB2018100909?affChecked=1");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_adobe_technical_comm_suite_detect_win.nasl");
  script_mandatory_keys("AdobeTCS/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
tcsVer = infos['version'];
tcsPath = infos['location'];

if(version_is_less(version:tcsVer, test_version:"7.1.57"))
{
  report = report_fixed_ver(installed_version:tcsVer, fixed_version:"2019 Release", install_path:tcsPath);
  security_message(data:report);
  exit(0);
}
exit(99);
