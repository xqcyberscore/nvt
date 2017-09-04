###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_awredir_mult_xss_vuln.nasl 7029 2017-08-31 11:51:40Z teissa $
#
# AWStats 'awredir.pl' Multiple Cross-Site Scripting Vulnerabilities
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

tag_impact = "Successful exploitation will allow remote attackers to insert
arbitrary HTML and script code, which will be executed in a user's browser
session in the context of an affected site.

Impact Level: Application";

tag_affected = "AWStats version 6.95 and 7.0";

tag_insight = "Multiple flaws are due to improper validation of user-supplied
input via the 'url' and 'key' parameters to awredir.pl, which allows attackers
to execute arbitrary HTML and script code in a user's browser session in the
context of an affected site.";

tag_solution = "Upgrade to version 7.1 or later,
For updates refer to http://awstats.sourceforge.net";

tag_summary = "This host is running AWStats and is prone to multiple cross site
scripting vulnerabilities.";

if(description)
{
  script_id(802251);
  script_version("$Revision: 7029 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-31 13:51:40 +0200 (Thu, 31 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-10-04 16:55:13 +0200 (Tue, 04 Oct 2011)");
  script_bugtraq_id(49749);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("AWStats 'awredir.pl' Multiple Cross-Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://websecurity.com.ua/5380/");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/46160");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105307/awstats-sqlxsssplit.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("awstats_detect.nasl");
  script_require_ports("Services/www", 80);
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

## Get AWStats Location
if(!dir = get_dir_from_kb(port:port, app:"awstats")){
  exit(0);
}

## Construct Attack Request
url = dir + "/awredir.pl?url=<script>alert(document.cookie)</script>";

## Try XSS and check the response to confirm vulnerability
if(http_vuln_check(port: port, url: url, check_header: TRUE,
   pattern: "<script>alert\(document.cookie\)</script>")) {
  security_message(port);
}
