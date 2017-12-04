###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_fields_info_disc_vuln_nov17.nasl 7968 2017-12-01 08:26:28Z asteins $
#
# Joomla! Core 'com_fields' Information Disclosure Vulnerability Nov17
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811898");
  script_version("$Revision: 7968 $");
  script_cve_id("CVE-2017-16633");
  script_bugtraq_id(101702);
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-12-01 09:26:28 +0100 (Fri, 01 Dec 2017) $");
  script_tag(name:"creation_date", value:"2017-11-08 11:42:00 +0530 (Wed, 08 Nov 2017)");
  script_name("Joomla! Core 'com_fields' Information Disclosure Vulnerability Nov17");

  script_tag(name:"summary", value:"This host is running Joomla and is prone
  to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to a logic bug in 
  'com_fields'.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allow
  remote attackers to gain access to sensitive information that may aid in 
  further attacks.

  Impact Level: Application");

  script_tag(name:"affected", value:"Joomla core version 3.7.0 through 3.8.1");

  script_tag(name:"solution", value:"Upgrade to Joomla version 3.8.2 or later.
  For updates refer to https://www.joomla.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name : "URL" , value : "https://developer.joomla.org/security-centre/715-20171103-core-information-disclosure.html");

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
jPort = "";
jVer = "";

## get the port
if(!jPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!jVer = get_app_version(cpe:CPE, port:jPort)){
  exit(0);
}

## Check for version
if(jVer =~ "^(3\.)")
{
  if(version_in_range(version:jVer, test_version:"3.7.0", test_version2:"3.8.1"))
  {
    report = report_fixed_ver( installed_version:jVer, fixed_version:"3.8.2");
    security_message( data:report, port:jPort);
    exit(0);
  }
}
exit(0);