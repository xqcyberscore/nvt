###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_campsite_sql_inj_vuln.nasl 8510 2018-01-24 07:57:42Z teissa $
#
# Campsite 'article_id' Parameter SQL Injection Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_solution = "Apply patch or Upgrade to Campsite version 3.3.6 or later,
  http://www.sourcefabric.org/en/home/web/6/campsite.htm?tpl=18
  http://www.sourcefabric.org/en/home/web_news/65/important-security-patch-for-campsite-3.2-and-above.htm?tpl=32

  *****
  NOTE: Please ignore the warning if the patch is applied.
  *****";

tag_impact = "Successful exploitation will allow attacker to manipulate SQL queries by
  injecting arbitrary SQL code, which leads to view, add, modify or delete
  information in the back-end database.
  Impact Level: Application";
tag_affected = "Campsite version 3.3.5 and prior";
tag_insight = "The flaw is due to improper validation of user supplied input via the
  'article_id' parameter to 'javascript/tinymce/plugins/campsiteattachment/attachments.php',
  which is not properly sanitised before being used in SQL queries.";
tag_summary = "This host is running Campsite and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902072");
  script_version("$Revision: 8510 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-24 08:57:42 +0100 (Wed, 24 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_cve_id("CVE-2010-1867");
  script_bugtraq_id(39862);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Campsite 'article_id' Parameter SQL Injection Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/39580");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/58285");
  script_xref(name : "URL" , value : "http://php-security.org/2010/05/01/mops-2010-002-campsite-tinymce-article-attachment-sql-injection-vulnerability/index.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_campsite_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

csPort = get_http_port(default:80);
if(!csPort){
  exit(0);
}

## Get the version from KB
csVer = get_kb_item("www/"+ csPort + "/Campsite");
if(!csVer){
  exit(0);
}

csVer = eregmatch(pattern:"^(.+) under (/.*)$", string:csVer);
if(csVer[1] != NULL)
{
  # Check for Campsite version <= 3.3.5
  if(version_is_less_equal(version:csVer[1], test_version:"3.3.5")){
    security_message(csPort);
  }
}
