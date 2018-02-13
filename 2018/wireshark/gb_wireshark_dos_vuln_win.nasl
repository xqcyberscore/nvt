###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_dos_vuln_win.nasl 8747 2018-02-09 14:42:20Z asteins $
#
# Wireshark Denial of Service Vulnerability (Windows)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112213");
  script_version("$Revision: 8747 $");
  script_cve_id("CVE-2018-6836");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-02-09 15:42:20 +0100 (Fri, 09 Feb 2018) $");
  script_tag(name:"creation_date", value:"2018-02-09 15:34:57 +0100 (Fri, 09 Feb 2018)");

  script_name("Wireshark Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"This host is installed with Wireshark
  and is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value: "Get the installed version with the
  help of the detect NVT and check if the version is vulnerable or not.");

  script_tag(name:"insight", value:"The netmonrec_comment_destroy function in wiretap/netmon.c in Wireshark performs a free operation
  on an uninitialized memory address, which allows remote attackers to cause a denial of service (application crash) or possibly have unspecified other impact.");

  script_tag(name:"impact", value:"Successful exploitation of this vulnerability
  will allow remote attackers to cause a denial of service or possible have unspecified other impact.

  Impact Level: Application.");

  script_tag(name:"affected", value: "Wireshark up to and including version 2.4.4 on Windows.");

  script_tag(name:"solution", value: "No solution available as of 9th February, 2018. Information regarding this issue will be updated once the solution details are available.
  For updates refer to https://www.wireshark.org");

  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14397");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
ver = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:ver, test_version:"2.4.4")) {
  report = report_fixed_ver(installed_version:ver, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report);
  exit(0);
}

exit(0);
