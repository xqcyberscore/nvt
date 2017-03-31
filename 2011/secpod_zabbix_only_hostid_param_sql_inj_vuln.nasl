###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zabbix_only_hostid_param_sql_inj_vuln.nasl 3114 2016-04-19 10:07:15Z benallard $
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.902769";
CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3114 $");
  script_cve_id("CVE-2011-4674");
  script_bugtraq_id(50803);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:07:15 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-12-15 11:10:21 +0530 (Thu, 15 Dec 2011)");
  script_name("Zabbix 'only_hostid' Parameter SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/45502/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71479");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18155/");
  script_xref(name : "URL" , value : "https://support.zabbix.com/browse/ZBX-4385");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check if Zabbix is vulnerable to SQL Injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("zabbix_web_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Zabbix/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct the Attack Request
url = dir + "/popup.php?dstfrm=form_scenario&dstfld1=application&srctbl=" +
               "applications&srcfld1=name&only_hostid='";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"You have an error in your " +
                                               "SQL syntax;")){
  security_message(port);
}
