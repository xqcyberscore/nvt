###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_49103.nasl 4711 2016-12-08 10:12:18Z cfi $
#
# Adobe Flash Media Server Memory Corruption Remote Denial of Service Vulnerability
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

CPE = "cpe:/a:adobe:flash_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103192");
  script_version("$Revision: 4711 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-08 11:12:18 +0100 (Thu, 08 Dec 2016) $");
  script_tag(name:"creation_date", value:"2011-08-10 15:25:18 +0200 (Wed, 10 Aug 2011)");
  script_bugtraq_id(49103);
  script_cve_id("CVE-2010-2132");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Adobe Flash Media Server Memory Corruption Remote Denial of Service Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_require_ports("Services/www", 1111);
  script_mandatory_keys("Adobe/FMS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49103");
  script_xref(name:"URL", value:"http://www.adobe.com/products/flashmediaserver/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-20.html");

  tag_summary = "Adobe Flash Media Server is prone to a remote denial-of-service
  vulnerability.";

  tag_impact = "Successful exploits will allow attackers to crash the affected
  application, denying service to legitimate users. Due to the nature of
  this issue, arbitrary code execution may be possible; this has not been confirmed.";

  tag_solution = "The vendor has released an advisory and updates. Please see the
  references for details.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"4.0", test_version2:"4.0.2" ) ||
    version_is_less( version:vers, test_version:"3.5.7" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See vendor advisory" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );