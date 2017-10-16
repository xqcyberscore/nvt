###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_ts_http2_feature_mult_unspec_vuln.nasl 7424 2017-10-13 09:34:30Z santu $
#
# Apache Traffic Server 'HTTP/2' Multiple Unspecified Vulnerabilities
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apache:traffic_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811852");
  script_version("$Revision: 7424 $");
  script_cve_id("CVE-2015-5206", "CVE-2015-5168");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2017-10-13 11:34:30 +0200 (Fri, 13 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-05 13:01:42 +0530 (Thu, 05 Oct 2017)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Apache Traffic Server 'HTTP/2' Multiple Unspecified Vulnerabilities");

  script_tag(name:"summary", value:"This host is installed with Apache Traffic Server
  and is prone to multiple unspecified vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple unspecified
  errors in 'HTTP/2 experimental feature'.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause unknown impacts on the target system.

  Impact Level: Application");

  script_tag(name:"affected", value:"Apache Traffic Server versions 5.3.x before 5.3.2");

  script_tag(name:"solution", value:"Upgrade to Apache Traffic Server version 
  5.3.2 or later, For updates refer to http://trafficserver.apache.org");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://mail-archives.us.apache.org/mod_mbox/www-announce/201509.mbox/%3CCABF6JR2j5vesvnjbm6sDPB_zAGj3kNgzzHEpLUh6dWG6t8mC2w@mail.gmail.com%3E");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_traffic_detect.nasl");
  script_mandatory_keys("apache_trafficserver/installed");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
trPort = "";
trVer = "";

## get the port
if(!trPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!trVer = get_app_version(cpe:CPE, port:trPort)){
  exit(0);
}

## Grep for vulnerable version
if (trVer == "5.3.0" || trVer == "5.3.1")
{
  report = report_fixed_ver(installed_version:trVer, fixed_version:"5.3.2");
  security_message(data:report, port:trPort);
  exit(0);
}

exit(0);
