###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_phpmyadmin_db_xss_vuln.nasl 7015 2017-08-28 11:51:24Z teissa $
#
# phpMyAdmin 'db' Parameter Stored Cross Site Scripting Vulnerability
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

tag_impact = "Successful exploitation will allow attackers to plant XSS backdoors and
  inject arbitrary SQL statements via crafted XSS payloads.
  Impact Level: Application";
tag_affected = "phpMyAdmin versions 3.4.x before 3.4.0 beta 3";
tag_insight = "The flaw is caused by improper validation of user-supplied input passed in
  the 'db' parameter to 'index.php', which allows attackers to execute arbitrary
  HTML and script code on the web server.";
tag_solution = "Upgrade to phpMyAdmin version 3.4.0 beta 3 or later.
  For updates refer to http://www.phpmyadmin.net/home_page/downloads.php";
tag_summary = "The host is running phpMyAdmin and is prone to Cross-Site Scripting
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801851";
CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7015 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-28 13:51:24 +0200 (Mon, 28 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_name("phpMyAdmin 'db' Parameter Stored Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/97906/phpmyadmin34-xss.txt");
  script_xref(name : "URL" , value : "http://bl0g.yehg.net/2011/01/phpmyadmin-34x-340-beta-2-stored-cross.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("phpMyAdmin/installed");
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
include("host_details.inc");

## Get phpMyAdmin Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Get phpMyAdmin Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct the Attack Request
url = string(dir,"/index.php?db=%27%22--%3E%3C%2Fscript%3E%3Cscript%3Ealert%" +
                 "28%2FXSS%2F%29%3C%2Fscript%3E");

## Try attack and check the response to confirm vulnerability
if(buf = http_vuln_check(port:port, url:url, pattern:"<script>alert\(/XSS/\)</",
                   check_header: TRUE)){

  if('\"--' >< buf)exit(99); # db:"\'\"--></' + 'script><script>alert(/XSS/)</' + 'script>",token: <- because of the \' and \" version 4.0.4.1 is NOT vulnerable

  security_message(port);
}
