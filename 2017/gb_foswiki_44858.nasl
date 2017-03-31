###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foswiki_44858.nasl 5132 2017-01-30 07:08:27Z antu123 $
#
# Foswiki Topic Settings Remote Privilege Escalation Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:foswiki:foswiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108059");
  script_version("$Revision: 5132 $");
  script_bugtraq_id(44858);
  script_tag(name:"last_modification", value:"$Date: 2017-01-30 08:08:27 +0100 (Mon, 30 Jan 2017) $");
  script_tag(name:"creation_date", value:"2017-01-27 13:41:11 +0100 (Fri, 27 Jan 2017)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4215");
  script_name("Foswiki Topic Settings Remote Privilege Escalation Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_foswiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Foswiki/installed");

  script_xref(name:"URL", value:"http://foswiki.org/Support/SecurityAlert-CVE-2010-4215");

  tag_impact = "Remote attackers with the ability to edit topic settings can exploit this
  issue to gain administrative privileges. This may aid in further attacks.";

  tag_affected = "Foswiki 1.1.0 and 1.1.1 are vulnerable.";

  tag_solution = "Upgrade to version 1.1.2 or later,
  http://foswiki.org/Download";

  tag_summary = "Foswiki is prone to a remote privilege-escalation vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"1.1.0", test_version2:"1.1.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );