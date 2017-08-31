##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_cmd_dos_vuln.nasl 6692 2017-07-12 09:57:43Z teissa $
#
# Nagios cmd.cgi Denial Of Service Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.804248";
CPE = "cpe:/a:nagios:nagios";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6692 $");
  script_cve_id("CVE-2014-1878");
  script_bugtraq_id(65605);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-07-12 11:57:43 +0200 (Wed, 12 Jul 2017) $");
  script_tag(name:"creation_date", value:"2014-03-18 12:05:18 +0530 (Tue, 18 Mar 2014)");
  script_name("Nagios cmd.cgi Denial Of Service Vulnerability");

  tag_summary =
"This host is running Nagios and is prone to denial of service vulnerability.";

  tag_vuldetect =
"Get the installed version of Nagios with the help of detect NVT and check the
version is vulnerable or not.";

  tag_insight =
"The flaw exists in cmd_submitf() function in cmd.cgi which fails to adequately
bounds-check user-supplied data before copying it into buffer";

  tag_impact =
"Successful exploitation will allow remote attackers to execute arbitrary code
or cause denial of service condition.

Impact Level: System/Application.";

  tag_affected =
"Nagios version before 4.0.3rc1 are affected.";

  tag_solution =
"Upgrade to version Nagios version 4.0.3rc1 or later.
For updates refer to http://www.nagios.org";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/57024");
  script_xref(name : "URL" , value : "http://www.cnnvd.org.cn/vulnerability/show/cv_id/2014020484");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("nagios_detect.nasl");
  script_mandatory_keys("nagios/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
http_port = 0;
ver = "";

## Get HTTP Port
if(!http_port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get Nagios Location
if(!ver = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:http_port)){
  exit(0);
}

if(version_is_less_equal(version:ver, test_version:"4.0.3"))
{
  security_message(http_port);
  exit(0);
}
