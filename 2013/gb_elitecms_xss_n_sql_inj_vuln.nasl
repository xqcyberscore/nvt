###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elitecms_xss_n_sql_inj_vuln.nasl 2939 2016-03-24 08:47:34Z benallard $
#
# Elite Graphix ElitCMS Cross Site Scripting and SQL Injection Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804029");
  script_version("$Revision: 2939 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-03-24 09:47:34 +0100 (Thu, 24 Mar 2016) $");
  script_tag(name:"creation_date", value:"2013-10-21 19:27:04 +0530 (Mon, 21 Oct 2013)");
  script_name("Elite Graphix ElitCMS Cross Site Scripting and SQL Injection Vulnerabilities");

  script_tag(name : "summary" , value : "This host is running Elite Graphix ElitCMS and is prone to xss and sql
  injection vulnerabilities.");
  script_tag(name : "vuldetect" , value : "Send a HTTP GET request and check whether it is able to execute sql query
  or not.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "insight" , value : "Multiple flaws are due to improper sanitation of user-supplied input passed
  via 'page' and 'subpage' parameters to index.php script.");
  script_tag(name : "affected" , value : "Elite Graphix ElitCMS version 1.01, Other versions may also be affected.");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code, inject or manipulate SQL queries in the back-end database
  allowing for the manipulation or disclosure of arbitrary data.

  Impact Level: Application");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123672");
  script_xref(name : "URL" , value : "http://www.vulnerability-lab.com/get_content.php?id=1117");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/elite-graphix-elitcms-101-pro-cross-site-scripting-sql-injection");
  script_summary("Check if Elite Graphix ElitCMS is prone to sql injection");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
http_port = "";
req = "";
res = "";
url = "";

## Get HTTP Port
http_port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:http_port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list_unique("/", "/elite", "/cms", "/elitecms", cgi_dirs(port:http_port)))
{

  if(dir == "/") dir = "";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port:http_port, url: dir + "/admin/login.php",
                     check_header: TRUE, pattern:">EliteCMS"))
  {
    ## Malformed URL
    url = dir + "/index.php?page=-1'SQL-Injection-Test";

    if(http_vuln_check(port:http_port, url: url, check_header: TRUE,
                       pattern:"Database Query failed !.*SQL-Injection-Test"))
    {
      security_message(port:http_port);
      exit(0);
    }
  }
}

exit(99);