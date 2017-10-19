###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_universal_cmdb_xss_n_code_exec_vuln.nasl 7497 2017-10-19 07:06:06Z santu $
#
# HPE Universal CMDB Remote Code Execution And XSS Vulnerabilities
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

CPE = "cpe:/a:hp:universal_cmbd_foundation";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811867");
  script_version("$Revision: 7497 $");
  script_cve_id("CVE-2017-14354", "CVE-2017-14353");
  script_bugtraq_id(101254, 101251);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-10-19 09:06:06 +0200 (Thu, 19 Oct 2017) $");
  script_tag(name:"creation_date", value:"2017-10-16 13:04:54 +0530 (Mon, 16 Oct 2017)");
  ## Not able to differentiate between patched and unpatched versions
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("HPE Universal CMDB Remote Code Execution And XSS Vulnerabilities");

  script_tag(name: "summary" , value:"The host is installed with HP Universal 
  CMDB and is prone to remote cross site scripting and code execution 
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Get the installed version with the help
  of detect NVT and check the version is vulnerable or not.");

  script_tag(name: "insight" , value:"Multiple flaws are due to multiple
  unspecified input validation errors in an unknown function.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote 
  attackers to execute arbitrary script code in the browser of an unsuspecting
  user in the context of the affected site and execute arbitrary code, which may
  lead to further attacks.

  Impact Level: System/Application");

  script_tag(name:"affected", value:"HPE Universal CMDB server versions 
  v10.10, v10.11, v10.20, v10.21, v10.22, v10.30, v10.31, v10.32, v10.33");

  script_tag(name:"solution", value:"Apply appropriate patch from below link
  https://softwaresupport.hpe.com/group/softwaresupport/search-result/-/facetsearch/document/KM02966345?lang=en&cc=us&hpappid=202392_SSO_PRO_HPE");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name : "URL" , value : "https://softwaresupport.hpe.com/km/KM02977984");
  script_xref(name : "URL" , value : "https://www.auscert.org.au/bulletins/53150");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hpe_universal_cmdb_detect.nasl");
  script_mandatory_keys("HP/UCMDB/Installed");
  script_require_ports("Services/www", 8080);
  exit(0);
}


##
### Code Starts Here
##

include("version_func.inc");
include("host_details.inc");

## Variable Initialization
ucmdbPort = "";
ucmdbVer = "";

## Get HTTP Port
if(!ucmdbPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!ucmdbVer = get_app_version(cpe:CPE, port:ucmdbPort)){
  exit(0);
}

##Check for vulnerable version
affected = make_list('10.10', '10.11', '10.20', '10.21', '10.22', '10.30', '10.31', '10.32', '10.33');

foreach version (affected)
{
  if(ucmdbVer == version)
  {
    report = report_fixed_ver(installed_version:ucmdbVer, fixed_version:"Apply the appropriate patch");
    security_message(data:report, port:ucmdbPort);
    exit(0);
  }
}
exit(0);
