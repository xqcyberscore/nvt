##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_otrs_mult_xss_mult_vuln.nasl 7044 2017-09-01 11:50:59Z teissa $
#
# Open Ticket Request System (OTRS) Multiple Cross-site scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801778";
CPE = "cpe:/a:otrs:otrs";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7044 $");
  script_cve_id("CVE-2011-1518");
  script_bugtraq_id(47323);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"last_modification", value:"$Date: 2017-09-01 13:50:59 +0200 (Fri, 01 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)");
  script_name("Open Ticket Request System (OTRS) Multiple Cross-site scripting Vulnerabilities");

tag_summary =
"This host is running Open Ticket Request System (OTRS) and is prone to
multiple Cross-site scripting Vulnerabilities.";

tag_vuldetect =
"Get the installed version of OTRS with the help of detect NVT and check the
version is vulnerable or not.";

tag_insight =
"The flaw is caused by improper validation of user-supplied input by multiple
scripts. A remote attacker could exploit this vulnerability using various
parameters in a specially-crafted URL to execute script in a victim's Web
browser within the security context of the hosting Web site.";

tag_impact =
"Successful exploitation will allow attackers to insert arbitrary HTML and
script code, which will be executed in a user's browser session in context
of an affected site and steal cookie-based authentication credentials.

Impact Level: Application";

tag_affected =
"Open Ticket Request System (OTRS) version 2.4.x before 2.4.10 and 3.x before 3.0.7";

tag_solution =
"Upgrade to Open Ticket Request System (OTRS) version 2.4.10 or 3.0.7 or later
For updates refer to http://otrs.org/download/ or Apply patch from the vendor
advisory link http://otrs.org/advisory/OSA-2011-01-en";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/44029");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/66698");
  script_xref(name : "URL" , value : "http://otrs.org/advisory/OSA-2011-01-en/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_otrs_detect.nasl");
  script_mandatory_keys("OTRS/installed");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");
include("global_settings.inc");

## Variable initialisation
port = "";
vers = "";

## Get Application HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Get application version
if(vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))
{

  if(version_in_range(version:vers, test_version:"2.4.0", test_version2:"2.4.9")||
     version_in_range(version:vers, test_version:"3.0.0", test_version2:"3.0.6"))
   {
      security_message(port);
   }
}
