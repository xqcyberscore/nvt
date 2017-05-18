###############################################################################
# OpenVAS Vulnerability Test
# $Id: xoops_37860.nasl 5952 2017-04-13 12:34:17Z cfi $
#
# XOOPS Arbitrary File Deletion and HTTP Header Injection Vulnerabilities
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

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100459");
  script_version("$Revision: 5952 $");
  script_tag(name:"last_modification", value:"$Date: 2017-04-13 14:34:17 +0200 (Thu, 13 Apr 2017) $");
  script_tag(name:"creation_date", value:"2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)");
  script_bugtraq_id(37860);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("XOOPS Arbitrary File Deletion and HTTP Header Injection Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37860");
  script_xref(name:"URL", value:"http://www.codescanlabs.com/research/advisories/xoops-2-4-3-vulnerability/");
  script_xref(name:"URL", value:"http://www.xoops.org");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/509034");

  tag_summary = "XOOPS is prone to an HTTP-header-injection vulnerability and an arbitrary-file-
  deletion vulnerability.";

  tag_insight = "By inserting arbitrary headers into an HTTP response, attackers may be
  able to launch various attacks, including cross-site request forgery,
  cross-site scripting, and HTTP-request smuggling.";

  tag_impact = "Successful file-deletion exploits may corrupt data and cause denial-of-
  service conditions.";

  tag_affected = "XOOPS 2.4.3 is vulnerable; other versions may also be affected.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected" , value:tag_affected);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"2.4.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"unknown" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
