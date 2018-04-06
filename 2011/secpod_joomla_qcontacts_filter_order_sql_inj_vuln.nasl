##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_qcontacts_filter_order_sql_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla! QContacts Component 'filter_order' Parameter SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will let attackers to cause SQL Injection
attack and gain sensitive information.

Impact Level: Application";

tag_affected = "Joomla! QContacts Component version 1.0.6";

tag_insight = "The flaw is caused by improper validation of user-supplied input
via the 'filter_order' parameter to index.php, which allows attacker to
manipulate SQL queries by injecting arbitrary SQL code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla! QContacts component and is prone to
SQL injection vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902594");
  script_version("$Revision: 9351 $");
  script_bugtraq_id(50981);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-12-13 12:12:12 +0530 (Tue, 13 Dec 2011)");
  script_name("Joomla! QContacts Component 'filter_order' Parameter SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71707");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18218");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/107650/joomlaqcontacts106-sql.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Joomla Directory
if(!dir = get_dir_from_kb(port:port,app:"joomla")) {
  exit(0);
}

## Construct the Attack Request
url = dir + "/index.php?option=com_qcontacts?=catid=0&filter_order=[SQLi]" +
            "&filter_order_Dir=&option=com_qcontacts";

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header: TRUE,
   pattern:"mysql_num_rows\(\): supplied argument is not a valid MySQL")){
  security_message(port);
}
