###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zabbix_only_hostid_param_sql_inj_vuln.nasl 7650 2017-11-03 13:34:50Z cfischer $
#
# Zabbix 'only_hostid' Parameter SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902769");
  script_version("$Revision: 7650 $");
  script_cve_id("CVE-2011-4674");
  script_bugtraq_id(50803);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-11-03 14:34:50 +0100 (Fri, 03 Nov 2017) $");
  script_tag(name:"creation_date", value:"2011-12-15 11:10:21 +0530 (Thu, 15 Dec 2011)");
  script_name("Zabbix 'only_hostid' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("zabbix_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Zabbix/Web/installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45502/");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/71479");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18155/");
  script_xref(name:"URL", value:"https://support.zabbix.com/browse/ZBX-4385");

  tag_impact = "Successful exploitation will allow attacker to perform SQL Injection attack
  and gain sensitive information.

  Impact Level: Application";

  tag_affected = "Zabbix version 1.8.4 and prior";

  tag_insight = "The flaw is due to improper validation of user-supplied input passed
  via the 'only_hostid' parameter to 'popup.php', which allows attackers to
  manipulate SQL queries by injecting arbitrary SQL code.";

  tag_solution = "Upgrade to Zabbix version 1.8.9 or later
  For updates refer to http://www.zabbix.com/index.php";

  tag_summary = "This host is running Zabbix and is prone to SQL injection
  vulnerability.";

  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);
  script_tag(name:"insight", value:tag_insight);
  script_tag(name:"solution", value:tag_solution);
  script_tag(name:"summary", value:tag_summary);

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + "/popup.php?dstfrm=form_scenario&dstfld1=application&srctbl=applications&srcfld1=name&only_hostid='";
if( http_vuln_check( port:port, url:url, pattern:"You have an error in your SQL syntax;" ) ) {
  report = report_vuln_url( port:port, url:url );
  security_message( port:port, data:report );
  exit( 0 );
}  

exit( 99 );