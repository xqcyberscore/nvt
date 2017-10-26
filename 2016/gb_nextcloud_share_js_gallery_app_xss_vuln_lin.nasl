###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nextcloud_share_js_gallery_app_xss_vuln_lin.nasl 7545 2017-10-24 11:45:30Z cfischer $
#
# nextCloud 'share.js' Gallery Application XSS Vulnerability (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.809415");
  script_version("$Revision: 7545 $");
  script_cve_id("CVE-2016-7419", "CVE-2016-9459", "CVE-2016-9460", "CVE-2016-9461", "CVE-2016-9462");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-24 13:45:30 +0200 (Tue, 24 Oct 2017) $");
  script_tag(name:"creation_date", value:"2016-09-27 13:01:29 +0530 (Tue, 27 Sep 2016)");
  script_name("nextCloud 'share.js' Gallery Application XSS Vulnerability (Linux)");

  script_tag(name: "summary" , value:"The host is installed with nextCloud and
  is prone to cross-site scripting (XSS) vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exists due to a recent migration
  of the gallery app to the new sharing endpoint and a parameter changed from an
  integer to a string value which is not sanitized properly.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  authenticated users to inject arbitrary web script or HTML.

  Impact Level: Application");

  script_tag(name: "affected" , value:"nextCloud Server before 9.0.52 on Linux.");

  script_tag(name: "solution" , value:"Upgrade to nextCloud Server 9.0.52 or later.
  For updates refer to http://nextcloud.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "https://nextcloud.com/security/advisory/?id=nc-sa-2016-001");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_nextcloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("nextcloud/installed", "Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
nextPort = "";
nextVer = "";

## get the port
if(!nextPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get version
if(!nextVer = get_app_version(cpe:CPE, port:nextPort)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:nextVer, test_version:"9.0.52"))
{
  report = report_fixed_ver(installed_version:nextVer, fixed_version:"9.0.52");
  security_message(data:report, port:nextPort);
  exit(0);
}
exit(0);
