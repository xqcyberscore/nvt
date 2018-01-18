###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_siteengine_sql_inj_vuln.nasl 8438 2018-01-16 17:38:23Z teissa $
#
# SiteEngine 'module' SQL Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to cause SQL
Injection attack and gain sensitive information.

Impact Level: Application";

tag_affected = "SiteEngine Version 7.1";

tag_insight = "The flaw is caused by improper validation of user-supplied input
via the 'module' parameter in comments.php that allows attackers to manipulate
SQL queries by injecting arbitrary SQL code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running SiteEngine and is prone to SQL injection
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801682");
  script_version("$Revision: 8438 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-16 18:38:23 +0100 (Tue, 16 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-12-31 07:04:16 +0100 (Fri, 31 Dec 2010)");
  script_bugtraq_id(45056);
  script_cve_id("CVE-2010-4357");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("SiteEngine 'module' SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42353");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/15612");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_siteengine_detect.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get Version from KB
seVer = get_version_from_kb(port:port, app:"SiteEngine");
if(! seVer) {
  exit(0);
}

## Check for SiteEngine Version
if(version_is_equal(version:seVer, test_version:"7.1")){
  security_message(0);
}
