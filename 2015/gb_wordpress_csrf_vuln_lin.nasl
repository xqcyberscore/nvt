###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_csrf_vuln_lin.nasl 9303 2018-04-04 13:18:17Z asteins $
#
# WordPress 'admin impersonation via comments' CSRF Vulnerability (Linux)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805947");
  script_version("$Revision: 9303 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-04 15:18:17 +0200 (Wed, 04 Apr 2018) $");
  script_tag(name:"creation_date", value:"2015-08-07 11:50:02 +0530 (Fri, 07 Aug 2015)");
  script_name("WordPress 'admin impersonation via comments' CSRF Vulnerability (Linux)");

  script_tag(name:"summary", value:"This host is running WordPress and is prone
  to cross-site request forgery vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The error exists as the application does not
  require a nonce value when posting comments.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to impersonate the admin via comments.

  Impact Level: Application");

  script_tag(name:"affected", value:"WordPress versions 3.8.1, 3.8.2 and 4.2.2
  on Linux.");

  script_tag(name:"solution", value:"Upgrade to WordPress version 4.3.1
  or later, For updates refer to https://wordpress.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2015/Aug/10");
  script_xref(name : "URL" , value : "https://security.dxw.com/advisories/comment-form-csrf-allows-admin-impersonation-via-comments-in-wordpress-4-2-2/");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("os_detection.nasl", "secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed","Host/runs_unixoide");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
wpPort = "";
wpName = "";
wpVer = "";

## get the port
if(!wpPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!wpVer = get_app_version(cpe:CPE, port:wpPort)){
  exit(0);
}

## Check for version
if(version_is_equal(version:wpVer, test_version:"4.2.2")||
   version_is_equal(version:wpVer, test_version:"3.8.2")||
   version_is_equal(version:wpVer, test_version:"3.8.1"))
{
  report = 'Installed Version: ' + wpVer + '\n' +
           'Fixed Version:      4.3.1\n';

  security_message(data:report, port:wpPort);
  exit(0);
}
