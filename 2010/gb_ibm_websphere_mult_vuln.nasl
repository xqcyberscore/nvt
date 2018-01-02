###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_mult_vuln.nasl 8250 2017-12-27 07:29:15Z teissa $
#
# IBM WebSphere Application Server multiple vulnerabilities.
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
###############################################################################

tag_summary = "IBM WebSphere Application Server (WAS) is prone to multiple
vulnerabilities.

1. A cross-site scripting vulnerability because the application fails to properly
sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may let the attacker steal cookie-based authentication
credentials and launch other attacks.

2. A Remote Denial Of Service Vulnerability.

Exploiting this issue allows remote attackers to cause WAS ORB threads
to hang, denying service to legitimate users. 

Versions prior to WAS 7.0.0.9, 6.1.0.31, and 6.0.2.4 are vulnerable.";

tag_solution = "The vendor has released updates. Please see the references for
details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100565");
 script_version("$Revision: 8250 $");
 script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
 script_tag(name:"creation_date", value:"2010-04-01 13:43:26 +0200 (Thu, 01 Apr 2010)");
 script_bugtraq_id(39051,39056);
 script_cve_id("CVE-2010-0768","CVE-2010-0770","CVE-2010-0769");

 script_name("IBM WebSphere Application Server multiple vulnerabilities");


 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_ibm_websphere_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39051");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/39056");
 script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27004980");
 script_xref(name : "URL" , value : "http://www-306.ibm.com/software/websphere/#");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57164");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57182");
 exit(0);
}
     
include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

CPE = 'cpe:/a:ibm:websphere_application_server';

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if(version_in_range(version: vers, test_version: "7",   test_version2: "7.0.0.8")   ||
   version_in_range(version: vers, test_version: "6.1", test_version2: "6.1.0.30")  ||
   version_in_range(version: vers, test_version: "6.0", test_version2: "6.0.2.40")) {
   report = report_fixed_ver( installed_version:vers, fixed_version:'See advisory' );
   security_message(port:0, data:report);
}

exit(0);

