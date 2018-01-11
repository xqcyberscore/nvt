###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pligg_mult_sql_inj_vuln.nasl 8338 2018-01-09 08:00:38Z teissa $
#
# Pligg Multiple SQL Injection Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Upadated By: Antu Sanadi <santu@secpod.com>  on 2010-08-16
#  - Added the CVE-2010-3013.
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "Pligg CMS Version 1.1.0 and prior.";
tag_insight = "The flaws are caused by improper validation of user-supplied inputs via the
  'title' parameter in storyrss.php and story.php and 'role' parameter in
  groupadmin.php that allows attacker to manipulate SQL queries by injecting
  arbitrary SQL code.";
tag_solution = "Upgrade to Pligg CMS Version 1.1.1 or later.
  For updates refer to http://www.pligg.com/download/";
tag_summary = "The host is running Pligg CMS and is prone to multiple SQL injection
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801258");
  script_version("$Revision: 8338 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-09 09:00:38 +0100 (Tue, 09 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-16 09:09:42 +0200 (Mon, 16 Aug 2010)");
  script_cve_id("CVE-2010-2577", "CVE-2010-3013");
  script_bugtraq_id(42408);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Pligg Multiple SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40931");
  script_xref(name : "URL" , value : "http://secunia.com/secunia_research/2010-111/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("pligg_cms_detect.nasl");
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

## Get Pligg Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check for Pligg Version prior to 1.1.1
if(ver = get_version_from_kb(port:port,app:"pligg"))
{
  if(version_is_less(version:ver, test_version:"1.1.1")){
    security_message(port:port);
  }
}
