###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_centreon_file_upload_vuln_june16.nasl 5513 2017-03-08 10:00:24Z teissa $
#
# Centreon 'POST' Parameter File Upload Vulnerability
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

CPE = "cpe:/a:centreon:centreon";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.808216");
  script_version("$Revision: 5513 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-03-08 11:00:24 +0100 (Wed, 08 Mar 2017) $");
  script_tag(name:"creation_date", value:"2016-06-07 16:34:51 +0530 (Tue, 07 Jun 2016)");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("Centreon 'POST' Parameter File Upload Vulnerability");

  script_tag(name: "summary" , value:"The host is installed with Centreon
  and is prone to file upload vulnerability.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"The flaw is due to the POST parameter
  'persistant' which serves for making a new service run  in the background
  is not properly sanitised before being used to execute commands.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary PHP code by uploading a malicious PHP script file.

  Impact Level: Application");

  script_tag(name:"affected", value:"Centreon version 2.6.1");

  script_tag(name:"solution", value:"Upgrad to Centreon version 2.6.2 or later. 
  For updates refer to https://www.centreon.com ");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/38339");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2015-5265.php"); 

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("centreon_detect.nasl");
  script_mandatory_keys("centreon/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

##
### Code Starts Here
##

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
cenPort = "";
cenVer = "";

## Get HTTP Port
if(!cenPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!cenVer = get_app_version(cpe:CPE, port:cenPort)){
  exit(0);
}

##Check for vulnerable version
if(version_is_equal(version:cenVer, test_version:"2.6.1"))
{
  report = report_fixed_ver(installed_version:cenVer, fixed_version:"2.6.2");
  security_message(data:report, port:cenPort);
  exit(0);
}
