##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_barter_sites_category_id_param_sql_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla! Barter Sites 'com_listing' Component 'category_id' Parameter SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

Impact Level: Application.";

tag_affected = "Joomla! Barter Sites Component Version 1.3";

tag_insight = "The flaw is caused by improper validation of user-supplied input
via the 'category_id' parameter to index.php (when 'option' is set to
'com_listing' and 'task' is set to 'browse'), which allows attacker to
manipulate SQL queries by injecting arbitrary SQL code.";

tag_solution = "Update to version 1.3.2 or later,
For updates refer to http://www.barter-sites.com";

tag_summary = "This host is running Joomla! Barter Sites component and is prone
to SQL injection vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802268");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2011-4829", "CVE-2011-4830");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-04 12:12:12 +0530 (Fri, 04 Nov 2011)");
  script_bugtraq_id(50021);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla! Barter Sites 'com_listing' Component 'category_id' Parameter SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46368");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18046");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/105626/joomlabarter-sqlxss.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("joomla/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
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
url = dir + "/index.php?option=com_listing&task=browse&category_id=1'";

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header: TRUE,
                   pattern:"Invalid argument supplied for foreach\(\)",
                   extra_check:">Warning<")){
  security_message(port);
}
