###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sqlitemanager_mult_xss_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# SQLiteManager 'dbsel' And 'nsextt' Parameters Multiple XSS Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site.

Impact Level: Application";

tag_affected = "SQLiteManager version 1.2.4 and prior.";

tag_insight = "The flaws are due to improper validation of user-supplied input
via the 'dbsel' or 'nsextt' parameters to index.php or main.php script, which
allows attacker to execute arbitrary HTML and script code on the user's
browser session in the security context of an affected site.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running SQLiteManager and is prone to multiple
cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802373");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-5105");
  script_bugtraq_id(51294);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-06 13:17:25 +0530 (Fri, 06 Jan 2012)");
  script_name("SQLiteManager 'dbsel' And 'nsextt' Parameters Multiple XSS Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/521126");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/108393/sqlitemanager124-xss.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_sqlitemanager_detect.nasl");
  script_require_ports("Services/www", 80);
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

## Get the HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

## Get the version from KB
dir = get_dir_from_kb(port:port,app:"SQLiteManager");
if(!dir){
  exit(0);
}

## Construct the Attack Request
url = dir + "/main.php?dbsel=</script><script>alert(document.cookie)</script>";

## Send XSS attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"</script><script>alert\(" +
                               "document.cookie\)</script>", check_header: TRUE)){
  security_message(port);
}
