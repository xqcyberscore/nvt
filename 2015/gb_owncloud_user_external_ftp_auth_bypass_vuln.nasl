###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_owncloud_user_external_ftp_auth_bypass_vuln.nasl 6391 2017-06-21 09:59:48Z teissa $
#
# ownCloud FTP Backend 'user_external' Password Authentication Bypass Vulnerability
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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805281");
  script_version("$Revision: 6391 $");
  script_cve_id("CVE-2014-9045");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-06-21 11:59:48 +0200 (Wed, 21 Jun 2017) $");
  script_tag(name:"creation_date", value:"2015-02-19 16:04:16 +0530 (Thu, 19 Feb 2015)");
  script_name("ownCloud FTP Backend 'user_external' Password Authentication Bypass Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with ownCloud and
  is prone to authentication bypass vulnerability");

  script_tag(name: "vuldetect" , value:"Get the installed version with the
  help of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The error exists due to a flaw in the
  user_external FTP backend provider that is triggered as URL-encoding on
  passwords is not properly performed");

  script_tag(name: "impact" , value:"Successful exploitation will allow
  remote attackers to bypass authentication and login to the remote server.

  Impact Level: Application");

  script_tag(name: "affected" , value:"ownCloud Server 5.x before 5.0.18 and
  6.x before 6.0.6");

  script_tag(name: "solution" , value:"Upgrade to ownCloud Server 5.0.18 or
  6.0.6 or later. For updates refer to http://owncloud.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://owncloud.org/security/advisory/?id=oc-sa-2014-022");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
ownPort = "";
ownVer = "";

## get the port
if(!ownPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get version
if(!ownVer = get_app_version(cpe:CPE, port:ownPort)){
  exit(0);
}

if(ownVer =~ "^(5|6)")
{
  ## Grep for vulnerable version
  if(version_in_range(version:ownVer, test_version:"5.0.0", test_version2:"5.0.17"))
  {
    fix = "5.0.18";
    VULN = TRUE;
  }

  if(version_in_range(version:ownVer, test_version:"6.0.0", test_version2:"6.0.5"))
  {
    fix = "6.0.6";
    VULN = TRUE;
  }

  if(VULN)
  {
    report = 'Installed version: ' + ownVer + '\n' +
             'Fixed version:     ' + fix + '\n';

    security_message(data:report);
    exit(0);
  }
}
