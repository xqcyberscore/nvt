###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_mod_lua_dos_vuln.nasl 7834 2017-11-20 14:48:51Z cfischer $
#
# Apache HTTP Server Mod_Lua Denial of service Vulnerability May15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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

CPE = "cpe:/a:apache:http_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805637");
  script_version("$Revision: 7834 $");
  script_cve_id("CVE-2014-8109");
  script_bugtraq_id(73040);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-11-20 15:48:51 +0100 (Mon, 20 Nov 2017) $");
  script_tag(name:"creation_date", value:"2015-05-27 12:15:46 +0530 (Wed, 27 May 2015)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # Only vulnerable if mod_lua is enabled
  script_name("Apache HTTP Server Mod_Lua Denial of service Vulnerability May15");

  script_tag(name:"summary", value:"This host is installed with Apache HTTP Server
  and is prone to denial of service  vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Flaw is due to a vulnerability in
  LuaAuthzProvider that is triggered if a user-supplied LUA script is supplied
  more than once with different arguments.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attackers to bypass intended access restrictions in opportunistic
  circumstances by leveraging multiple Require directives.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache HTTP Server version 2.3.x through
  2.4.10.");

  script_tag(name:"solution", value:"Upgrade to version 2.4.12 or
  later, For updates refer http://www.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://httpd.apache.org/security/vulnerabilities_24.html");
  script_xref(name : "URL" , value : "http://www.rapid7.com/db/vulnerabilities/apache-httpd-cve-2014-8109");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("secpod_apache_detect.nasl");
  script_mandatory_keys("apache/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
httpd_port = 0;
httpd_ver = "";

## Get HTTP Port
if(!httpd_port = get_app_port(cpe:CPE)){
  exit(0);
}

## Get Version
if(!httpd_ver = get_app_version(cpe:CPE, port:httpd_port)){
  exit(0);
}

## Checking for Vulnerable version
if(version_in_range(version:httpd_ver, test_version:"2.3.0", test_version2:"2.4.10"))
{
  report = 'Installed version: ' + httpd_ver + '\n' +
           'Fixed version:     ' + "2.4.12" + '\n';
  security_message(data:report, port:httpd_port);
  exit(0);
}
