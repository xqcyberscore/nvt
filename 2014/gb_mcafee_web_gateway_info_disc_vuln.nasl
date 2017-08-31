###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mcafee_web_gateway_info_disc_vuln.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# McAfee Web Gateway Information Disclosure Vulnerability
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:mcafee:web_gateway";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804839");
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2014-6064");
  script_bugtraq_id(69556);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-09-09 17:31:29 +0530 (Tue, 09 Sep 2014)");

  script_name("McAfee Web Gateway Information Disclosure Vulnerability");

  script_tag(name: "summary" , value:"This host is installed with McAfee Web
  Gateway and is prone to information disclosure vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version of McAfee Web
  Gateway with the help of detect NVT and check the version is vulnerable or
  not.");

  script_tag(name: "insight" , value: "The flaw is due to an error in admin
  interface while viewing the top level Accounts tab");

  script_tag(name: "impact" , value: "Successful exploitation will allow an
  authenticated remote attacker to gain access to SHA1 hashed MWG administrator
  password information.

  Impact Level: Application");

  script_tag(name: "affected" , value: "McAfee Web Gateway before 7.3.2.9 and
  7.4.x before 7.4.2");

  script_tag(name: "solution" , value: "Upgrade to McAfee Web Gateway version
  7.3.2.9 or 7.4.2 or later, For updates refer to http://www.mcafee.com/us");

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id/1030675");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_mcafee_web_gateway_detect.nasl");
  script_mandatory_keys("McAfee/Web/Gateway/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialization
mwgPort = "";
mwgVer = "";

## Get Application HTTP Port
if(!mwgPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get application version
mwgVer = get_app_version(cpe:CPE, port:mwgPort);
if(!mwgVer){
  exit(0);
}

if(version_is_less(version:mwgVer, test_version:"7.3.2.9"))
{
  security_message(port:mwgPort);
  exit(0);
}

if(mwgVer =~ "^7\.4")
{
  if(version_is_less(version:mwgVer, test_version:"7.4.2"))
  {
    security_message(port:mwgPort);
    exit(0);
  }
}

