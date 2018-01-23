###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_websphere_40699.nasl 8495 2018-01-23 07:57:49Z teissa $
#
# IBM WebSphere Application Server 'addNode.log' Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
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

tag_summary = "IBM WebSphere Application Server (WAS) is prone to an information-
disclosure vulnerability.

A local authenticated attacker can exploit this issue to gain access
to sensitive information; this may aid in further attacks.

 Versions prior to WAS 7.0.0.11 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100671");
 script_version("$Revision: 8495 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-06-10 10:47:44 +0200 (Thu, 10 Jun 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2326");
 script_bugtraq_id(40699);

 script_name("IBM WebSphere Application Server 'addNode.log' Information Disclosure Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/40699");
 script_xref(name : "URL" , value : "http://www-306.ibm.com/software/websphere/#");
 script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PM10684");
 script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg1PM15830");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("General");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("gb_ibm_websphere_detect.nasl");
 script_require_ports("Services/www", 80);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

CPE = 'cpe:/a:ibm:websphere_application_server';

if( ! vers = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

if(version_in_range(version: vers, test_version: "7", test_version2: "7.0.0.10")) {
  report = report_fixed_ver( installed_version:vers, fixed_version:'7.0.0.11' );
  security_message(port:0, data:report);
  exit(0);
}

exit(0);
