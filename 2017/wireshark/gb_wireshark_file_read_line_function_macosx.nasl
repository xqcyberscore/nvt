###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wireshark_file_read_line_function_macosx.nasl 8263 2017-12-29 15:35:55Z santu $
#
# Wireshark 'File_read_line' Function Denial of Service Vulnerability (Mac OS X)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com> 
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

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812282");
  script_version("$Revision: 8263 $");
  script_cve_id("CVE-2017-17935");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-12-29 16:35:55 +0100 (Fri, 29 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-12-28 12:52:35 +0530 (Thu, 28 Dec 2017)");
  script_name("Wireshark 'File_read_line' Function Denial of Service Vulnerability (Mac OS X)");

  script_tag(name: "summary" , value:"This host is installed with Wireshark
  and is prone to denial of service vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to a buffer underflow 
  error in 'File_read_line' function in 'epan/wslua/wslua_file.c' file.");

  script_tag(name: "impact" , value:"Successful exploitation of this
  vulnerability will allow remote attackers to cause a denial of service.

  Impact Level: Application.");

  script_tag(name: "affected" , value: "Wireshark version through 2.2.11 on 
  Mac OS X.");

  script_tag(name: "solution" , value: "No solution or patch is available as of
  28th Dec, 2017. Information regarding this issue will be updated once solution
  details are available. For updates refer to https://www.wireshark.org");

  script_xref(name : "URL" , value : "https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=14295");
 
  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

wirversion = "";
path = "";
infos = "";

infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE );
wirversion = infos['version'];
path = infos['location'];

if(version_is_less_equal(version:wirversion, test_version:"2.2.11"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"NoneAvailable", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(0);
