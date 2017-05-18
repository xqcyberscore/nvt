###################################################################
# OpenVAS Vulnerability Test
# $Id: openca_mult_sign_flaws.nasl 6063 2017-05-03 09:03:05Z teissa $
#
# OpenCA multiple signature validation bypass
#
# Authors:
# David Maciejak <david dot maciejak at kyxar dot fr>
# based on work from Tenable Network Security
#
# Copyright:
# Copyright (C) 2004 David Maciejak
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###################################################################

CPE = "cpe:/a:openca:openca";

# Ref: Chris Covell and Gottfried Scheckenbach

if(description) {

  script_oid("1.3.6.1.4.1.25623.1.0.14714");
  script_version("$Revision: 6063 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-03 11:03:05 +0200 (Wed, 03 May 2017) $");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_bugtraq_id(9123);
  script_cve_id("CVE-2003-0960");
  script_xref(name:"OSVDB", value:"2884");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("OpenCA multiple signature validation bypass");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2004 David Maciejak");
  script_family("Web application abuses");
  script_dependencies("gb_openca_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openca/installed");

  tag_summary = "The remote host seems to be running an older version of OpenCA. 

  It is reported that OpenCA versions up to and incluing 0.9.1.3 contains 
  multiple flaws that may allow revoked or expired certificates to be accepted as valid.";

  tag_solution = "Upgrade to the newest version of this software";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less_equal( version:vers, test_version:"0.9.1.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"N/A" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );