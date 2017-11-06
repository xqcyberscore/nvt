###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_50803.nasl 7651 2017-11-03 13:41:18Z cfischer $
#
# ZABBIX 'only_hostid' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103348");
  script_bugtraq_id(50803);
  script_cve_id("CVE-2011-4674");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 7651 $");
  script_name("ZABBIX 'only_hostid' Parameter SQL Injection Vulnerability");
  script_tag(name:"last_modification", value:"$Date: 2017-11-03 14:41:18 +0100 (Fri, 03 Nov 2017) $");
  script_tag(name:"creation_date", value:"2011-11-30 11:34:16 +0100 (Wed, 30 Nov 2011)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("zabbix_detect.nasl", "zabbix_web_detect.nasl"); # nb: Only the Web-GUI is providing a version
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Zabbix/Web/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50803");
  script_xref(name:"URL", value:"http://www.zabbix.com/index.php");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-4385");

  tag_summary = "ZABBIX is prone to an SQL-injection vulnerability because it fails
  to sufficiently sanitize user-supplied data before using it in an
  SQL query.";

  tag_impact = "Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database.";

  tag_affected = "ZABBIX versions 1.8.3 and 1.8.4 are vulnerable.";

  tag_solution = "Updates are available. Please see the references for more details.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"solution", value:tag_solution);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"1.8.3" ) ||
    version_is_equal( version:vers, test_version:"1.8.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );