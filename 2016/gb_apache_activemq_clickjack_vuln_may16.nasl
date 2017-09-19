###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_clickjack_vuln_may16.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Apache ActiveMQ Clickjacking Vulnerability May16
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

CPE = "cpe:/a:apache:activemq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807971");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2016-0734");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-05-05 17:11:01 +0530 (Thu, 05 May 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache ActiveMQ Clickjacking Vulnerability May16");

  script_tag(name:"summary", value:"This host is running Apache ActiveMQ and is
  prone to clickjacking vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists as the web-based
  administration console does not set an X-Frame-Options header in HTTP
  responses.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct clickjacking attacks via a crafted web page.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache ActiveMQ Version 5.x before 5.13.2.");

  script_tag(name:"solution", value:"Upgrade to Apache ActiveMQ Version 5.13.2 or
  later. For updates refer to http://activemq.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://activemq.apache.org/security-advisories.data/CVE-2016-0734-announcement.txt");

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_apache_activemq_detect.nasl");
  script_require_ports("Services/www", 8161);
  script_mandatory_keys("ActiveMQ/installed");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
appVer = "";
appPort = "";

## Get Port
if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get version
if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

## Check the vulnerable version 
if(version_in_range(version:appVer, test_version:"5.0.0", test_version2:"5.13.1"))
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:"5.13.2");
  security_message(data:report, port:appPort);
  exit(0);
}
