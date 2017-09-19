###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cybozu_mailwise_buffer_overflow_vuln.nasl 7174 2017-09-18 11:48:08Z asteins $
#
# Cybozu Mailwise Buffer Overflow Vulnerability Feb16
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

CPE = "cpe:/a:cybozu:mailwise";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807422");
  script_version("$Revision: 7174 $");
  script_cve_id("CVE-2014-5314");
  script_bugtraq_id(71057);
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-09-18 13:48:08 +0200 (Mon, 18 Sep 2017) $");
  script_tag(name:"creation_date", value:"2016-03-03 18:24:00 +0530 (Thu, 03 Mar 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Cybozu Mailwise Buffer Overflow Vulnerability Feb16");

  script_tag(name:"summary" , value:"The host is installed with Cybozu Mailwise
  and is prone to buffer overflow vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help of
  detect nvt and check the version is vulnerable or not.");

  script_tag(name:"insight" , value:"The flaw exists due to an unspecified
  Buffer Overflow vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause denial-of-service, or execute arbitrary code.

  Impact Level: Application");

  script_tag(name:"affected", value:"Cybozu Mailwise version 5.1.3 and earlier.");
  script_tag(name:"solution", value:"Upgrade to Cybozu Mailwise version 5.1.4
  or later, For updates refer to http://products.cybozu.co.jp/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://jvn.jp/en/jp/JVN14691234/index.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_cybozu_products_detect.nasl");
  script_mandatory_keys("CybozuMailWise/Installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

## Variable Initialization
cybVer = "";

## Get version
if(!cybPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(!cybVer = get_app_version(port:cybPort, cpe:CPE)){
  exit(0);
}

## Grep for vulnerable version
if(version_is_less(version:cybVer, test_version:"5.1.4"))
{
  report = report_fixed_ver(installed_version:cybVer, fixed_version:"5.1.4");
  security_message(port:cybPort, data:report);
  exit(0);
}

exit(99);
