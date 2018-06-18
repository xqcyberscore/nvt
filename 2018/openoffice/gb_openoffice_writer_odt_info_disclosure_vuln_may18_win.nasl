###############################################################################                                                                 # OpenVAS Vulnerability Test
# $Id: gb_openoffice_writer_odt_info_disclosure_vuln_may18_win.nasl 10231 2018-06-18 03:58:33Z ckuersteiner $
#
# Apache OpenOffice Writer ODT file Information Disclosure Vulnerability May18 (Windows)
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

CPE = "cpe:/a:openoffice:openoffice.org";

if(description)                                                                                                                                 {
  script_oid("1.3.6.1.4.1.25623.1.0.812873");
  script_version("$Revision: 10231 $");
  script_cve_id("CVE-2018-10583");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-06-18 05:58:33 +0200 (Mon, 18 Jun 2018) $");
  script_tag(name:"creation_date", value:"2018-05-07 15:19:54 +0530 (Mon, 07 May 2018)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Apache OpenOffice Writer ODT file Information Disclosure Vulnerability May18 (Windows)");

  script_tag(name:"summary", value:"This host is installed with Apache OpenOffice
  Writer and is prone to information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists within an 
  office:document-content element in a .odt XML document.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to automatically process and initiate an SMB connection embedded in a malicious
  .odt file and leak NetNTLM credentials.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache OpenOffice Writer version 4.1.5 on
  Windows.");

  script_tag(name:"solution", value:"No known solution is available as of 11th May, 2018.
  Information regarding this issue will be updated once solution details are available.
  For updates refer to Reference links.");

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_xref(name:"URL", value:"http://secureyourit.co.uk/wp/2018/05/01/creating-malicious-odt-files/");
  script_xref(name:"URL", value:"https://www.openoffice.org/");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_openoffice_detect_win.nasl");
  script_mandatory_keys("OpenOffice/Win/Ver"); 
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE);
over = infos['version'];
opath = infos['location'];

if(over == "4.15.9789")
{
  report = report_fixed_ver(installed_version:over, fixed_version:"NoneAvailable", install_path:opath);
  security_message(data:report);
  exit(0);
}
exit(0);
