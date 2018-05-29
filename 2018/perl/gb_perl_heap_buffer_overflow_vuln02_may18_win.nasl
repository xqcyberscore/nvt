###############################################################################                                                                 # OpenVAS Vulnerability Test
# $Id: gb_perl_heap_buffer_overflow_vuln02_may18_win.nasl 9988 2018-05-28 15:16:14Z cfischer $
#
# Perl Heap-Based Buffer Overflow Vulnerability - 02 May18 (Windows)
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

CPE = "cpe:/a:perl:perl";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812887");
  script_version("$Revision: 9988 $");
  script_cve_id("CVE-2018-6797");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-05-28 17:16:14 +0200 (Mon, 28 May 2018) $");
  script_tag(name:"creation_date", value:"2018-05-18 17:20:41 +0530 (Fri, 18 May 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Perl Heap-Based Buffer Overflow Vulnerability - 02 May18 (Windows)");

  script_tag(name:"summary", value:"This host is running Perl and is
  prone to heap-based buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists because Perl unable to
  sanitize against a crafted regular expression.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code on the target system or cause the target system to
  crash.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"Perl versions from 5.18 through 5.26 on
  Windows.");

  script_tag(name:"solution", value:"Upgrade to Perl version 5.26.2 or
  later. For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://rt.perl.org/Public/Bug/Display.html?id=131844");
  script_xref(name:"URL", value:"https://www.perl.org/get.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("gb_perl_detect_win.nasl");
  script_mandatory_keys("Perl/Strawberry_or_Active/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
pver = infos['version'];
ppath = infos['location'];

if(version_in_range( version:pver, test_version:"5.18", test_version2:"5.26" ))
{
  report = report_fixed_ver(installed_version:pver, fixed_version:"5.26.2", install_path:ppath);
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
