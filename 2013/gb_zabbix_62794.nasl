###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_62794.nasl 7650 2017-11-03 13:34:50Z cfischer $
#
# ZABBIX API and Frontend  Multiple SQL Injection Vulnerabilities
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

CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103812");
  script_bugtraq_id(62794) ;
  script_cve_id("CVE-2013-5743");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 7650 $");
  script_name("ZABBIX API and Frontend  Multiple SQL Injection Vulnerabilities");
  script_tag(name:"last_modification", value:"$Date: 2017-11-03 14:34:50 +0100 (Fri, 03 Nov 2017) $");
  script_tag(name:"creation_date", value:"2013-10-15 14:09:10 +0200 (Tue, 15 Oct 2013)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("zabbix_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Zabbix/Web/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62794");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-7091");

  tag_insight = "A remote attacker could send specially-crafted SQL statements
  to multiple API methods using multiple parameters, which could allow the
  attacker to view, add, modify or delete information in the back-end database.";

  tag_impact = "A successful exploit may allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities
  in the underlying database.";

  tag_affected = "ZABBIX prior to 2.0.9

  ZABBIX prior to 1.8.18 ";

  tag_summary = "ZABBIX API and Frontend are prone to multiple SQL-injection
  vulnerabilities.";

  tag_solution = "Updates are available. Please see the references or vendor advisory
  for more information.";

  tag_vuldetect = "Send a special crafted HTTP GET request and check the response.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"vuldetect", value:tag_vuldetect);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + '/httpmon.php?applications=2%27';
if( http_vuln_check( port:port, url:url, pattern:"Error in query", extra_check:"You have an error in your SQL syntax" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}  

exit( 99 );
