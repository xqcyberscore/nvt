###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nextcloud_cal_nd_addrbook_info_disclosure_vuln_lin.nasl 9085 2018-03-12 10:33:10Z cfischer $
#
# nextCloud 'Calender and Addressbook' Information Disclosure Vulnerability (Linux)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
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

CPE = "cpe:/a:nextcloud:nextcloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811135");
  script_version("$Revision: 9085 $");
  script_cve_id("CVE-2017-0895");
  script_bugtraq_id(98432);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-03-12 11:33:10 +0100 (Mon, 12 Mar 2018) $");
  script_tag(name:"creation_date", value:"2017-05-30 17:45:47 +0530 (Tue, 30 May 2017)");
  script_name("nextCloud 'Calender and Addressbook' Information Disclosure Vulnerability (Linux)");

  script_tag(name: "summary" , value:"The host is running nextCloud and is prone
  to information disclosure vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to some unspecified
  logical error.");

  script_tag(name: "impact" , value:"Successful exploitation will disclose the
  calendar and addressbook names to other logged-in users.

  Impact Level: Application");

  script_tag(name: "affected" , value:"nextCloud Server before 10.0.4 and 11.0.2
  on Linux.");

  script_tag(name: "solution" , value:"Upgrade to nextCloud Server 10.0.4, or
  11.0.2 or later. For updates refer to http://nextcloud.com");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name : "URL" , value : "https://nextcloud.com/security/advisory/?id=nc-sa-2017-012");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!nextPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!nextVer = get_app_version(cpe:CPE, port:nextPort)){
  exit(0);
}

if(nextVer =~ "^(9|10)\." && version_is_less(version:nextVer, test_version:"10.0.4")){
  fix = "10.0.4";
}

else if(nextVer =~ "^11\." && version_is_less(version:nextVer, test_version:"11.0.2")){
  fix = "11.0.2";
}

if(fix){
  report = report_fixed_ver(installed_version:nextVer, fixed_version:fix);
  security_message(data:report, port:nextPort);
  exit(0);
}

exit(99);