###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_was_45800.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# IBM WebSphere Application Server Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

tag_summary = "IBM WebSphere Application Server (WAS) is prone to an information-
disclosure vulnerability and to a cross-site scripting vulnerability.

This issue affects WAS 6.1 before 6.1.0.35 and 7.0 before 7.0.0.15.";

tag_solution = "Vendor updates are available. Please see the references for more
information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103029");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-01-14 14:24:22 +0100 (Fri, 14 Jan 2011)");
 script_bugtraq_id(45800,45802);
 script_cve_id("CVE-2011-0316","CVE-2011-0315");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_name("IBM WebSphere Application Server Multiple Vulnerabilities");


 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web Servers");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");

 script_dependencies("gb_ibm_websphere_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45800");
 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/45802");
 script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg27007951");
 script_xref(name : "URL" , value : "http://www-01.ibm.com/software/websphere/");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64558");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/64554");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58557");
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

CPE = 'cpe:/a:ibm:websphere_application_server';

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if(version_in_range(version: vers, test_version: "7.0", test_version2:"7.0.0.14")||
   version_in_range(version: vers, test_version: "6.0", test_version2:"6.1.0.34")) {
  report = report_fixed_ver( installed_version:vers, fixed_version:'7.0.0.15/6.1.0.35' );
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
