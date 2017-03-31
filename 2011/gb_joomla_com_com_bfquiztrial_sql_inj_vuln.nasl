##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_com_com_bfquiztrial_sql_inj_vuln.nasl 3117 2016-04-19 10:19:37Z benallard $
#
# Joomla 'BF Quiz' Component 'catid' Parameter SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will let attackers to manipulate SQL queries by
  injecting arbitrary SQL code.
  Impact Level: Application";
tag_affected = "Joomla BF Quiz (com_bfquiztrial) component prior to 1.3.1";
tag_insight = "The flaw is due to an input passed via the 'catid' parameter to
  'index.php' is not properly sanitised before being used in SQL queries.";
tag_solution = "Upgrade to Joomla BF Quiz component version 1.3.1 or later
  For updates refer to http://extensions.joomla.org/extensions/vertical-markets/education-a-culture/quiz/8142";
tag_summary = "This host is running Joomla! with BF Quiz component and is
  prone to SQL injection vulnerability.";

if(description)
{
  script_id(802535);
  script_version("$Revision: 3117 $");
  script_cve_id("CVE-2010-5032");
  script_bugtraq_id(40435);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-04-19 12:19:37 +0200 (Tue, 19 Apr 2016) $");
  script_tag(name:"creation_date", value:"2011-12-06 13:16:11 +0530 (Tue, 06 Dec 2011)");
  script_name("Joomla 'BF Quiz' Component 'catid' Parameter SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39960");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58979");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/90080/joomlabfquiz-sql.txt");
  script_xref(name : "URL" , value : "http://xenuser.org/documents/security/joomla_com_bfquiz_sqli.txt");

  script_tag(name:"qod_type", value:"remote_active");
  script_summary("Check if Joomla BF Quiz component is vulnerable for SQL Injection attack");
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
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Check host supports PHP
if(!can_host_php(port:joomlaPort)){
  exit(0);
}

## Get Installed Location
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Try attack and check the response to confirm vulnerability
url = string(joomlaDir, "/index.php?option=com_bfquiztrial&view=bfquiztrial&catid=1");

if(http_vuln_check(port:joomlaPort, url:url, pattern:"You have an error in " +
                                              "your SQL syntax;")){
 security_message(joomlaPort);
}
