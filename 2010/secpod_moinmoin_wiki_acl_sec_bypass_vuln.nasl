###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_moinmoin_wiki_acl_sec_bypass_vuln.nasl 8755 2018-02-12 06:56:14Z cfischer $
#
# MoinMoin Wiki ACL Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:moinmo:moinmoin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902154");
  script_version("$Revision: 8755 $");
  script_cve_id("CVE-2009-4762");
  script_tag(name:"last_modification", value:"$Date: 2018-02-12 07:56:14 +0100 (Mon, 12 Feb 2018) $");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MoinMoin Wiki Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("moinmoinWiki/installed");

  script_xref(name:"URL", value:"http://moinmo.in/SecurityFixes");
  script_xref(name:"URL", value:"http://hg.moinmo.in/moin/1.8/rev/897cdbe9e8f2");
  script_xref(name:"URL", value:"http://hg.moinmo.in/moin/1.7/rev/897cdbe9e8f2");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0266");

  tag_impact = "Successful exploitation will allow attackers to bypass intended access
  restrictions by requesting an item.

  Impact Level: Application";

  tag_affected = "MoinMoin Wiki version 1.7.x before 1.7.3 and 1.8.x before 1.8.3";

  tag_insight = "The flaw is due to error in checking the parent ACLs in certain
  inappropriate circumstances during processing of hierarchical ACLs.";

  tag_solution = "Upgrade to MoinMoin Wiki 1.7.3 or 1.8.3,

  For updates refer to http://moinmo.in/MoinMoinDownload";

  tag_summary = "This host is running MoinMoin Wiki and is prone to security bypass
  vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

## Check for version 1.7.x through 1.7.2, 1.8 through 1.8.2
if( version_in_range( version:vers, test_version:"1.7", test_version2:"1.7.2" ) ||
    version_in_range( version:vers, test_version:"1.8", test_version2:"1.8.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.7.3/1.8.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );