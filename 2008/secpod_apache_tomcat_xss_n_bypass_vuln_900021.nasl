##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_tomcat_xss_n_bypass_vuln_900021.nasl 4489 2016-11-14 08:23:54Z teissa $
# Description: Apache Tomcat Cross-Site Scripting and Security Bypass Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:apache:tomcat";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900021");
  script_version("$Revision: 4489 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-14 09:23:54 +0100 (Mon, 14 Nov 2016) $");
  script_tag(name:"creation_date", value:"2008-08-07 17:25:16 +0200 (Thu, 07 Aug 2008)");
  script_bugtraq_id(30494, 30496);
  script_cve_id("CVE-2008-1232", "CVE-2008-2370");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_category(ACT_GATHER_INFO);
  script_family("Web Servers");
  script_dependencies("gb_apache_tomcat_detect.nasl");
  script_mandatory_keys("ApacheTomcat/installed");
  script_require_ports("Services/www", 8080);

  script_name("Apache Tomcat Cross-Site Scripting and Security Bypass Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/31379/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/31381/");
 
  script_tag(name : "summary" , value : "This host is running Apache Tomcat web server, which is prone to
  cross site scripting and security bypass vulnerabilities.");
  script_tag(name : "insight" , value : "The flaws are due to,
  - input validation error in the method HttpServletResponse.sendError() which
  fails to properly sanitise before being returned to the user in the HTTP Reason-Phrase.
  - the application fails to normalize the target path before removing
  the query string when using a RequestDispatcher.");
  script_tag(name : "affected" , value : "Apache Tomcat 4.1.0 - 4.1.37, 5.5.0 - 5.5.26, and 6.0.0 - 6.0.16
  on All Platforms.");
  script_tag(name : "solution" , value : "Upgrade to higher version of 4.x, 5.x, or 6.x series.
  http://tomcat.apache.org/");
  script_tag(name : "impact" , value : "Successful exploitation could cause execution of arbitrary
  HTML code, script code, and information disclosure.

  Impact Level : Application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

## get the port
if(!appPort = get_app_port(cpe:CPE)){
  exit(0);
}

## Get the version
if(!appVer = get_app_version(cpe:CPE, port:appPort)){
  exit(0);
}

if(appVer =~ "^4\.0")
{
  if(version_in_range(version:appVer, test_version:"4.1.0", test_version2:"4.1.37"))
  {
    fix = "4.1.38";
    VULN = TRUE;
  }
}

if(appVer =~ "^5\.5")
{
  if(version_in_range(version:appVer, test_version:"5.5.0", test_version2:"5.5.26"))
  {
    fix = "5.5.27";
    VULN = TRUE;
  }
}

if(appVer =~ "^6\.0")
{
  if(version_in_range(version:appVer, test_version:"6.0.0", test_version2:"6.0.16"))
  {
    fix = "6.0.17";
    VULN = TRUE;
  }
}

if(VULN)
{
  report = 'Installed version: ' + appVer + '\n' +
           'Fixed version:     ' + fix  + '\n';
  security_message(data:report, port:appPort);
  exit(0);
}

exit(99);
