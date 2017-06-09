###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_information_disc_vuln_oct15.nasl 6159 2017-05-18 09:03:44Z teissa $
#
# TYPO3 Information Disclosure Vulnerability - Oct15
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
CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806601");
  script_version("$Revision: 6159 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-18 11:03:44 +0200 (Thu, 18 May 2017) $");
  script_tag(name:"creation_date", value:"2015-10-20 14:56:05 +0530 (Tue, 20 Oct 2015)");
  script_name("TYPO3 Information Disclosure Vulnerability - Oct15");

  script_tag(name: "summary" , value: "This host is installed with TYPO3 and
  is prone to information disclosure vulnerability.");

  script_tag(name: "vuldetect" , value: "Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value: "The flaw exists as no authentication is
  required to access certain pages for specific URLs.");

  script_tag(name: "impact" , value: "Successful exploitation will allow
  remote attackers to gain access to sensitive information.

  Impact Level: Application.");

  script_tag(name: "affected" , value:"TYPO3 versions 4.2 and 4.5");

  script_tag(name: "solution" , value:"No solution or patch was made available
  for at least one year since disclosure of this vulnerability. Likely none
  will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the
  product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name: "URL" , value : "https://packetstormsecurity.com/files/133961");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

## Variable initialisation
typoPort = "";
typoVer = "";

## Get Application HTTP Port
if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

##Get Typo3 version
if(!typoVer = get_app_version(cpe:CPE, port:typoPort)){
  exit(0);
}

if(typoVer !~ "[0-9]+\.[0-9]+") exit(0);

## Check for version 4.2 and 4.5
if(typoVer =~ "(4\.(2|5))")
{
  report = report_fixed_ver(installed_version:typoVer, fixed_version:"None Available");
  security_message(port:typoPort, data:report);
  exit(0);
}

exit(99);
