###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_activemq_webconsole_xss_vuln.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Apache ActiveMQ Web Console Cross-Site Scripting Vulnerability
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.808293");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2016-0782");
  script_bugtraq_id(84316);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-08-18 09:00:09 +0530 (Thu, 18 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache ActiveMQ Web Console Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"This host is running Apache ActiveMQ and is
  prone to a cross site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"The flaw exists due to an improper user data 
  output validation and incorrect permissions configured on Jolokia.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  authenticated attackers to conduct cross-site scripting (XSS) attacks and 
  consequently obtain sensitive information from a Java memory dump via 
  vectors related to creating a queue.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache ActiveMQ Version 5.x before 5.11.4, 
  5.12.x before 5.12.3, and 5.13.x before 5.13.1.");

  script_tag(name:"solution", value:"Upgrade to Apache ActiveMQ Version 
  5.11.4 or 5.12.3 or 5.13.1 or later. 
  For updates refer to http://activemq.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://packetstormsecurity.com/files/136215");
  script_xref(name : "URL" , value : "http://activemq.apache.org/security-advisories.data/CVE-2016-0782-announcement.txt");

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
if(version_in_range(version:appVer, test_version:"5.0.0", test_version2:"5.11.3"))
{
  fix = "5.11.4";
  VULN = TRUE ;
}
else if(version_in_range(version:appVer, test_version:"5.12.0", test_version2:"5.12.2"))
{
  fix = "5.12.3";
  VULN = TRUE ;
}
else if(version_is_equal(version:appVer, test_version:"5.13.0"))
{
  fix = "5.13.1";
  VULN = TRUE ;
}

if(VULN)
{
  report = report_fixed_ver(installed_version:appVer, fixed_version:fix);
  security_message(data:report, port:appPort);
  exit(0);
}
