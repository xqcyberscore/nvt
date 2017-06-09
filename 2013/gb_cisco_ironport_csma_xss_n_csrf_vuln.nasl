###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_ironport_csma_xss_n_csrf_vuln.nasl 6115 2017-05-12 09:03:25Z teissa $
#
# Cisco Content Security Management Appliance XSS and CSRF Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/h:cisco:content_security_management_appliance";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803754");
  script_version("$Revision: 6115 $");
  script_bugtraq_id(60919, 60829);
  script_cve_id("CVE-2013-3395", "CVE-2013-3396");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-12 11:03:25 +0200 (Fri, 12 May 2017) $");
  script_tag(name:"creation_date", value:"2013-09-04 11:53:49 +0530 (Wed, 04 Sep 2013)");
  script_name("Cisco Content Security Management Appliance XSS and CSRF Vulnerabilities");

 tag_summary =
"This host is running Cisco Content Security Management Appliance and is prone
to cross site scripting and cross site request forgery vulnerabilities.";

  tag_vuldetect =
"Get the installed version of Cisco Content Security Management Appliance with
the help of detect NVT and check the version is vulnerable or not.";

  tag_insight =
"Multiple flaws are due to,
- The lack of output escaping in the default error 500 page. When a exception
  occurs in the application, the error description contains user unvalidated
  input from the request.
- The lack of input validation on job_name, job_type, appliances_options and
  config_master parameters which are then printed unscapped on job_name,
  old_job_name, job_type, appliance_lists and config_master fields.
- The CSRFKey is not used in some areas of the application.";

  tag_impact =
"Successful exploitation will allow attacker to execute arbitrary script
code in the browser of an unsuspecting user in the context of the affected
site.

Impact Level: Application";

  tag_affected =
"Cisco Content Security Management Appliance (SMA) 8.1 and prior";

  tag_solution ="Upgrade to latest version of Cisco CSMA or Apply the patch,
For updates refer to http://www.cisco.com/en/US/products/ps12503/index.html ";


  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://1337day.com/exploit/21168");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122955");
  script_xref(name : "URL" , value : "http://tools.cisco.com/security/center/viewAlert.x?alertId=29844");
  script_xref(name : "URL" , value : "http://tools.cisco.com/security/center/content/CiscoSecurityNotice/CVE-2013-3396");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/cisco-ironport-cross-site-request-forgery-cross-site-scripting");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("CISCO");
  script_dependencies("gb_cisco_csma_version.nasl");
  script_mandatory_keys("cisco_csm/version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## Variable Initialization
csmaVer = "";
csmaPort = 0;

## Get Cisco Content Security Management Appliance (SMA) version
if(!csmaVer = get_app_version(cpe:CPE)){
  exit(0);
}

## check the vulnerable versions
if(csmaVer)
{
  csmaVer = str_replace(string: csmaVer, find:'-', replace:'.' );
  if(version_is_less_equal(version:csmaVer, test_version:"8.1.0"))
  {
    security_message(csmaPort);
    exit(0);
  }
}
