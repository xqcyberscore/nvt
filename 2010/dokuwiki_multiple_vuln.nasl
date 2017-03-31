###############################################################################
# OpenVAS Vulnerability Test
# $Id: dokuwiki_multiple_vuln.nasl 5145 2017-01-31 11:07:58Z cfi $
#
# DokuWiki Multiple Vulnerabilities
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

CPE = "cpe:/a:dokuwiki:dokuwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100451");
  script_version("$Revision: 5145 $");
  script_cve_id("CVE-2010-0287");
  script_bugtraq_id(37821, 37820);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-01-31 12:07:58 +0100 (Tue, 31 Jan 2017) $");
  script_tag(name:"creation_date", value:"2010-01-18 11:34:48 +0100 (Mon, 18 Jan 2010)");
  script_name("DokuWiki Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_dokuwiki_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dokuwiki/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37821");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37820");
  script_xref(name:"URL", value:"http://www.dokuwiki.org/");

  tag_summary = "DokuWiki is prone to an information-disclosure vulnerability and to
  multiple security-bypass vulnerabilities.";

  tag_impact = "Exploiting this issues may allow attackers to determine whether certain
  files reside on the affected computer. Information obtained may lead
  to further attacks. Unauthenticated attackers can leverage these
  issues to change or delete wiki permissions.";

  tag_affected = "This issue affects DokuWiki 2009-12-25; other versions may be
  vulnerable as well.";

  tag_solution = "Reports indicate that updates are available, but Symantec has not
  confirmed this information. Please see the references and contact the
  vendor for details.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
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

if( version_is_less( version:vers, test_version:"2009-12-25b" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2009-12-25b" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );