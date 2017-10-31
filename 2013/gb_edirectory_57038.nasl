###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_edirectory_57038.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# Novell eDirectory Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103630");
  script_bugtraq_id(57038);
  script_cve_id("CVE-2012-0428","CVE-2012-0429","CVE-2012-0430","CVE-2012-0432");
  script_version("$Revision: 7573 $");
  script_name("Novell eDirectory Multiple Security Vulnerabilities");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2013-01-02 11:38:11 +0100 (Wed, 02 Jan 2013)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("novell_edirectory_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("eDirectory/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57038");
  script_xref(name:"URL", value:"http://www.novell.com/products/edirectory/");
  script_xref(name:"URL", value:"http://www.novell.com/");

  tag_summary = "Novell eDirectory is prone to following multiple remote
  vulnerabilities:

  1. A cross-site scripting vulnerability
  2. A denial-of-service vulnerability
  3. An information-disclosure vulnerability
  4. A stack-based buffer-overflow vulnerability";

  tag_impact = "Exploiting these issues could allow an attacker to execute arbitrary
  script code in the browser of an unsuspecting user in the context of
  the affected site, steal cookie-based authentication credentials,
  disclose sensitive information, execute arbitrary code, cause a denial-of-
  service condition. Other attacks are possible.";

  tag_affected = "Novell eDirectory versions prior to 8.8.7.2 and 8.8.6.7 are
  vulnerable.";

  tag_solution = "An update is available. Please see the references for more
  information.";

  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

CPE = make_list( "cpe:/a:novell:edirectory","cpe:/a:netiq:edirectory" );

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! major = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( ! sp = get_kb_item( "ldap/eDirectory/" + port + "/sp" ) )
  sp = "0";

revision = get_kb_item( "ldap/eDirectory/" + port + "/build" );
revision = str_replace( string:revision, find:".", replace:"" );

invers = major;

if( sp > 0 )
  invers += ' SP' + sp;

if( major =~ "8\.8" )
{
  if( ! sp || sp < 6 ) hole = TRUE;
  if( sp == 6 && ( ! revision || revision < 20608 ) ) hole = TRUE;
  if( sp == 7 && ( ! revision || revision < 20703 ) ) hole = TRUE;

}

if( hole )
{
  report =  report_fixed_ver( installed_version:invers, fixed_version:"See advisory" );
  security_message( port:port, data:report );
  exit(0);
}

exit(99);
