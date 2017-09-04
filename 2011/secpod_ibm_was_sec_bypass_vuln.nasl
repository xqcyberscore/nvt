###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ibm_was_sec_bypass_vuln.nasl 7044 2017-09-01 11:50:59Z teissa $
#
# IBM WebSphere Application Server (WAS) Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation could allow an attacker to bypass the authentication
  process to and gain unauthorized access to the system with the privileges of
  the victim.
  Impact Level: Application";
tag_affected = "IBM WAS Version 6.1.0.9";
tag_insight = "The flaw is due to an error in invoking an internal login module, wlogin
  method, which is not properly handling an application hashtable login. This
  allows attackers to perform an internal application hashtable login by
  providing an empty password.";
tag_solution = "Upgrade to IBM WAS version 6.1.0.15 or later,
  For updates refer to http://www-01.ibm.com/support/docview.wss?uid=swg1PK54565";
tag_summary = "The host is running IBM WebSphere Application Server and is prone to security
  bypass vulnerability.";

if(description)
{
  script_id(902292);
  script_version("$Revision: 7044 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-01 13:50:59 +0200 (Fri, 01 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_cve_id("CVE-2008-7274");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("IBM WebSphere Application Server (WAS) Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PK54565");

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
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

CPE = 'cpe:/a:ibm:websphere_application_server';

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if(version_is_equal(version: vers, test_version:"6.1.0.9")){
  report = report_fixed_ver( installed_version:vers, fixed_version:'6.1.0.10' );
  security_message(port:0, data:report);
}
