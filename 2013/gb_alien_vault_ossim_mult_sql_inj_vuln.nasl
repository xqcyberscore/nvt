###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_alien_vault_ossim_mult_sql_inj_vuln.nasl 6104 2017-05-11 09:03:48Z teissa $
#
# AlienVault OSSIM 'date_from' Parameter Multiple SQL Injection Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:alienvault:open_source_security_information_management";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804028");
  script_version("$Revision: 6104 $");
  script_cve_id("CVE-2013-5967");
  script_bugtraq_id(62790);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-11 11:03:48 +0200 (Thu, 11 May 2017) $");
  script_tag(name:"creation_date", value:"2013-10-17 15:25:41 +0530 (Thu, 17 Oct 2013)");
  script_name("AlienVault OSSIM 'date_from' Parameter Multiple SQL Injection Vulnerabilities");

  script_tag(name:"summary", value:"This host is running AlienVault OSSIM and is prone to multiple sql injection
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"Send a HTTP GET request and check whether it is able to execute sql query
  or not.");
  script_tag(name:"solution", value:"Upgrade to version 4.4.0 or later,
  For updates refer to http://www.alienvault.com/open-threat-exchange/projects");
  script_tag(name:"insight", value:"Multiple flaws are due to improper sanitation of user-supplied input to the
  'date_form' parameter when displaying radar reports.");
  script_tag(name:"affected", value:"AlienVault Open Source Security Information Management (OSSIM) version 4.3
  and prior.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to inject or manipulate
  SQL queries in the back-end database, allowing for the manipulation or disclosure of arbitrary data.

  Impact Level: Application");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/87652");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ossim_web_detect.nasl");
  script_mandatory_keys("OSSIM/installed");
  script_require_ports("Services/www", 443);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

## Get HTTP Port
if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port) ) exit(0);

if( dir == "/" ) dir = "";

## Construct Malformed URL
url = dir + "/RadarReport/radar-iso27001-potential.php?date_from='SQL-Injection-Test";

## Construct Attack Request
req = http_get( item: url, port: port );
res = http_keepalive_send_recv( port:port, data:req );

## Check the response to confirm vulnerability
if( res && res =~ "You have an error in your SQL syntax.*SQL-Injection-Test"
        && "datawarehouse.ssi_user" >< res ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
