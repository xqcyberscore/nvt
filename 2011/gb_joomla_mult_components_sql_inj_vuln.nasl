##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_joomla_mult_components_sql_inj_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla Multiple Components SQL Injection Vulnerabilities
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
  Impact Level: Application.";
tag_affected = "Joomla Joostina component
  Joomla sgicatalog component
  Joomla Amblog component version 1.0
  Joomla Clantools Component version 1.2.3
  Joomla CamelcityDB component version 2.2
  Joomla Clantools Component version 1.2.3
  Joomla Restaurant Guide component version 1.0.0
  Joomla Aardvertiser Component versions 2.1 and 2.1.1";
tag_insight = "For more information about vulnerability refer the references section.";
tag_solution = "For solution or patch refer the refer section.
  For updates refer to http://extensions.joomla.org/extensions/";
tag_summary = "This host is running Joomla with multiple components and is
  prone to SQL injection vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802196");
  script_version("$Revision: 9351 $");
  script_cve_id("CVE-2010-4927", "CVE-2010-4928", "CVE-2010-4929", "CVE-2010-4937",
                "CVE-2010-4945", "CVE-2010-4902", "CVE-2010-4865", "CVE-2010-4902");
  script_bugtraq_id(43319, 33254, 43415, 42334, 42986, 43605,42986);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-11-03 15:42:01 +0200 (Thu, 03 Nov 2011)");
  script_name("Joomla Multiple Components SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40932");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41322");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/62151");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14530/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14596/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14530/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15040/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15157/");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14902/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/92305/joomlacamelcitydb2-sql.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/105704/joomlasgicatalog-sql.txt");

  script_tag(name:"qod_type", value:"remote_active");
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

## Make list of vulnerable pages
pages = make_list("/index.php?option=com_restaurantguide&view=country&id='&Itemid=69",
                  "/index.php?option=com_ezautos&Itemid=49&id=1&task=helpers&firstCode='",
                  "/index.php?option=com_amblog&task=editsave&articleid='",
                  "/index.php?option=com_camelcitydb2&view=all&Itemid=15",
                  "/index.php?option=com_jeguestbook&view=item_detail&d_itemid='",
                  "/index.php?option=com_clantools&squad='",
                  "'/index.php?option=com_sgicatalog&task=view&lang=en&id='",
                  "/index.php?option=com_aardvertiser&amp;cat_name='x+AND+'1'='1&amp;task=view");

foreach page (pages)
{
  if(http_vuln_check(port:joomlaPort, url: joomlaDir + page, pattern: "<b>" +
                 "Warning</b>:  Invalid argument supplied for foreach\(\)") ||
  (http_vuln_check(port:joomlaPort, url:joomlaDir + page, pattern:"You have an error in " +
                        "your SQL syntax;")))
  {
    security_message(joomlaPort);
    exit(0);
  }
}
