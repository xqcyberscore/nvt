###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_openid_access_control_bypass_vuln_lin.nasl 9638 2018-04-27 02:43:52Z ckuersteiner $
#
# ownCloud 'OpenID' Access Control Bypass Vulnerability (Linux)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813060");
  script_version("$Revision: 9638 $");
  script_cve_id("CVE-2014-2048");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 04:43:52 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2018-04-02 17:26:31 +0530 (Mon, 02 Apr 2018)");
  script_name("ownCloud 'OpenID' Access Control Bypass Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running ownCloud and is prone
  to an access control bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw is due to an insecure OpenID 
  implementation used by user_openid in ownCloud 5.");

  script_tag(name:"impact", value:"Successful exploitation allows remote 
  attackers to obtain access by leveraging an insecure OpenID implementation.

  Impact Level: Application");

  script_tag(name:"affected", value:"ownCloud versions prior to 5.0.15 on Linux.");

  script_tag(name:"solution", value:"Upgrade to ownCloud 5.0.15 or later.
  For updates refer to https://owncloud.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_xref(name : "URL" , value : "https://owncloud.org/security/advisories/insecure-openid-implementation");
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("owncloud/installed", "Host/runs_unixoide");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!owport = get_app_port(cpe:CPE)){
  exit(0);
}

infos = get_app_version_and_location(cpe:CPE, port:owport, exit_no_version:TRUE);
owVer = infos['version'];
path = infos['location'];

if(version_is_less(version:owVer, test_version:"5.0.15"))
{
  report = report_fixed_ver(installed_version:owVer, fixed_version: "5.0.15 or later", install_path:path);
  security_message(port:owport, data:report);
  exit(0);
}
exit(0);
