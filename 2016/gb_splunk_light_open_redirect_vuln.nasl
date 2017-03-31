###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_splunk_light_open_redirect_vuln.nasl 4105 2016-09-19 09:15:54Z ckuerste $
#
# Splunk Light Open Redirection Vulnerability
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

CPE = "cpe:/a:splunk:light";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809014");
  script_version("$Revision: 4105 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-09-19 11:15:54 +0200 (Mon, 19 Sep 2016) $");
  script_tag(name:"creation_date", value:"2016-08-26 17:00:30 +0530 (Fri, 26 Aug 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Splunk Light Open Redirection Vulnerability");

  script_cve_id("CVE-2016-4859");

  script_tag(name: "summary" , value:"This host is installed with 
  Splunk Light and is prone to an open redirection vulnerability.");

  script_tag(name: "vuldetect" , value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight", value:"The flaw is due to an unspecified input
  validation error.");

  script_tag(name: "impact" , value:"Successful exploitation of this vulnerability
  could permit an attacker to redirect a user to an attacker controlled website.
  
  Impact Level: Application");

  script_tag(name: "affected" , value:"Splunk Light version before 6.4.3");

  script_tag(name: "solution" , value:"Upgrade to Splunk Light version 6.4.3
  or later.
  For updates refer to http://www.splunk.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "http://www.splunk.com/view/SP-CAAAPQ6");
  
  script_summary("Check for the vulnerable version of Splunk Light");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_splunk_light_detect.nasl");
  script_mandatory_keys("SplunkLight/installed");
  script_require_ports("Services/www", 8000);
  exit(0);
}


##Code starts here

include("host_details.inc");
include("version_func.inc");

##variable initialization
splver = "";
splport = 0;

##Get Port
if(!splport = get_app_port(cpe:CPE)){
  exit(0);
}

## Get version
if(!splver = get_app_version(cpe:CPE, port:splport)){
  exit(0);
}

## Check Splunk Enterprise vulnerable versions
if(version_is_less(version:splver, test_version:"6.4.3"))
{
  report = report_fixed_ver(installed_version:splver, fixed_version:"6.4.3");
  security_message(data:report, port:splport);
  exit(0);
}
