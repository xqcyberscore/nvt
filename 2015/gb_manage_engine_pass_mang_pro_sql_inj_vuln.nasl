###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_pass_mang_pro_sql_inj_vuln.nasl 6254 2017-05-31 09:04:18Z teissa $
#
# ManageEngine Password Manager Pro SQL Injection Vulnerability
#
# Authors:
# Deependra Bapna <bdeepednra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:manageengine:password_manager_pro";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805715");
  script_version("$Revision: 6254 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-31 11:04:18 +0200 (Wed, 31 May 2017) $");
  script_tag(name:"creation_date", value:"2015-07-07 15:16:06 +0530 (Tue, 07 Jul 2015)");
  script_name("ManageEngine Password Manager Pro SQL injection Vulnerability");

  script_tag(name: "summary" , value:"This host is installed with ManageEngine
  Password Manager Pro and is prone to a SQL injection vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Flaw is due to error while escaping the
  operator when more then one condition is specified in the advanced search.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to inject or manipulate SQL queries in the back-end database,
  allowing for the manipulation or disclosure of arbitrary data.

  Impact Level: Application");

  script_tag(name: "affected" , value:"ManageEngine Password Manager
  Pro 8.1 Build 8100 and below.");

  script_tag(name: "solution" , value:"Upgrade to 8.1 Build 8101 or later.
  For updates refer to https://www.manageengine.com/products/passwordmanagerpro/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/132511");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/passwordmanagerpro/release-notes.html");

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_pass_mang_pro_detect.nasl");
  script_mandatory_keys("ManageEngine/Password_Manager/installed");
  script_require_ports("Services/www", 7272);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
meVer = "";
mePort = "";

## get the port
if(!mePort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!meVer = get_app_version(cpe:CPE, port:mePort)){
  exit(0);
}

##Check version is less than 8.1 build 8101
if(version_is_less(version:meVer, test_version:"8101"))
{
  report = 'Installed Version: ' + meVer + '\n' +
           'Fixed Version:     8.1 (Build 8101)\n';
  security_message(data:report, port:mePort);
  exit(0);
}
