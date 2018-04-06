###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xwiki_enterprise_mult_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# XWiki Enterprise Unspecified SQL Injection and XSS Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary script
  code or cause SQL Injection attack and gain sensitive information.
  Impact Level: Application";
tag_affected = "XWiki Enterprise before 2.5";
tag_insight = "The flaws are caused by input validation errors when processing user-supplied
  data and parameters, which could allow remote attackers to execute arbitrary
  script code or manipulate SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to XWiki Enterprise 2.5 or later,
  For updates refer to http://enterprise.xwiki.org/xwiki/bin/view/Main/";
tag_summary = "The host is running XWiki Enterprise and is prone to unspecified
  SQL injection and cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801841");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-08 15:34:31 +0100 (Tue, 08 Feb 2011)");
  script_cve_id("CVE-2010-4641", "CVE-2010-4642");
  script_bugtraq_id(44601);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("XWiki Enterprise Unspecified SQL Injection and XSS Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42058");
  script_xref(name : "URL" , value : "http://www.xwiki.org/xwiki/bin/view/ReleaseNotes/ReleaseNotesXWikiEnterprise25");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get Http Port
port = get_http_port(default:8080);
if(!port){
  exit(0);
}

## Check for XWiki Enterprise version prior to 2.5
if(ver = get_kb_item("www/" + port + "/XWiki"))
{
  if(version_is_less(version: ver, test_version: "2.5")){
    security_message(port:port);
  }
}
