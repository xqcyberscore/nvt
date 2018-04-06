##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_com_easyfaq_sql_inj_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Joomla 'com_easyfaq' Component Multiple SQL Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to cause SQL
Injection attack and gain sensitive information.

Impact Level: Application";

tag_affected = "Joomla! EasyFAQ Component";

tag_insight = "The flaws are due to improper validation of user-supplied input
passed via multiple parameters to 'index.php' (when 'option' is set to
'com_easyfaq'), which allows attacker to manipulate SQL queries by
injecting arbitrary SQL code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla EasyFAQ component and is prone to
multiple sql injection vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902827");
  script_version("$Revision: 9352 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-03-30 12:12:12 +0530 (Fri, 30 Mar 2012)");
  script_name("Joomla 'com_easyfaq' Component Multiple SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/17859");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_active");
  script_copyright("Copyright (C) 2012 SecPod");
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

## Variable Initialization
joomlaPort = 0;
joomlaDir = "";
url = "";

## Get HTTP Port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:joomlaPort)){
  exit(0);
}

## Get the application directory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Construct attack request
url = joomlaDir + "/index.php?option=com_easyfaq&task=view&contact_id='";

## Check the response to confirm vulnerability
if(http_vuln_check(port:joomlaPort, url:url, check_header:TRUE,
   pattern:"You have an error in your SQL syntax;")){
  security_message(joomlaPort);
}
