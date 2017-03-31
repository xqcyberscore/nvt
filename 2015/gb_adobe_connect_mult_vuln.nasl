###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_connect_mult_vuln.nasl 2582 2016-02-05 08:32:27Z benallard $
#
# Adobe Connect Multiple Vulnerabilities
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

CPE = "cpe:/a:adobe:connect";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805662");
  script_version("$Revision: 2582 $");
  script_cve_id("CVE-2015-0344", "CVE-2015-0343");
  script_bugtraq_id(75188, 75153);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-02-05 09:32:27 +0100 (Fri, 05 Feb 2016) $");
  script_tag(name:"creation_date", value:"2015-06-19 12:17:48 +0530 (Fri, 19 Jun 2015)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Adobe Connect Multiple Vulnerabilities");

  script_tag(name: "summary" , value:"The host is installed with Adobe Connect
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw exist due to multiple cross site
  scripting vulnerabilities in the web app in Adobe Connect");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary html or script code via the query parameter
  and some unspecified vectors.

  Impact Level: Application");

  script_tag(name:"affected", value:"Adobe Connect versions before 9.4");

  script_tag(name:"solution", value:"Upgrade to Adobe Connect version 9.4 or later,
  For updates refer to http://www.adobe.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2015/Jun/61");
  script_xref(name : "URL" , value : "https://helpx.adobe.com/adobe-connect/release-note/connect-94-release-notes.html");

  script_summary("Check for the vulnerable version of Adobe Connect");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_adobe_connect_detect.nasl");
  script_mandatory_keys("adobe/connect/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


##
### Code Starts Here
##

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
acPort = "";
acVer = "";
dir = "";

## Get HTTP Port
if(!acPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!acVer = get_app_version(cpe:CPE, port:acPort)){
  exit(0);
}

##Check for vulnerable version
if(version_is_less(version:acVer, test_version:"9.4"))
{
  report = 'Installed Version: ' + acVer + '\n' +
           'Fixed Version:     ' + "9.4" + '\n';
  security_message(data:report, port:acPort);
  exit(0);
}
