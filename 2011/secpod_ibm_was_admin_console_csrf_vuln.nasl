###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_was_admin_console_csrf_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM WebSphere Application Server Multiple CSRF Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote users to gain sensitive
information and conduct other malicious activities.

Impact Level: Application";

tag_affected = "IBM WebSphere Application Server (WAS) 7.0.0.13 and prior.";

tag_insight = "The flaws are due to by improper validation of user-supplied
input in the Global Security panel and master configuration save functionality.
which allows attacker to force a logged-in administrator to perform unwanted
actions.";

tag_solution = "Apply the patch from vendor link,
http://www-01.ibm.com/software/webservers/appserv/was/";

tag_summary = "The host is running IBM WebSphere Application Server and is
prone to cross-site request forgery vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902610");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-07-22 12:16:19 +0200 (Fri, 22 Jul 2011)");
  script_cve_id("CVE-2010-3271");
  script_bugtraq_id(48305);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("IBM WebSphere Application Server Multiple CSRF Vulnerabilities");


  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44909");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/68069");
  script_xref(name : "URL" , value : "http://www.coresecurity.com/content/IBM-WebSphere-CSRF");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

CPE = 'cpe:/a:ibm:websphere_application_server';

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

## Checking IBM WebSphere Application Server version 7.0.0.13 and prior
if(version_is_less_equal(version:vers, test_version:"7.0.0.13")){
  report = report_fixed_ver( installed_version:vers, fixed_version:'7.0.0.14' );
  security_message(port:0, data:report);
}
