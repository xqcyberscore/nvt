###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bugtracker_sql_inj_vuln.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# BugTracker.NET 'search.aspx' SQL Injection Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to cause SQL Injection attack
  and gain sensitive information.
  Impact Level: Application";
tag_affected = "BugTracker.NET version 3.4.3 and prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  custom field parameters to 'search.aspx' that allows attacker to manipulate
  SQL queries by injecting arbitrary SQL code.";
tag_solution = "Upgrade to BugTracker.NET version 3.4.4 or later,
  For updates refer to http://www.ifdefined.com/bugtrackernet_download.html";
tag_summary = "The host is running BugTracker.NET and is prone to SQL injection
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801279");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-09-15 08:47:45 +0200 (Wed, 15 Sep 2010)");
  script_bugtraq_id(42784);
  script_cve_id("CVE-2010-3188");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("BugTracker.NET 'search.aspx' SQL Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/41150");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/61434");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/513385/100/0/threaded");
  script_xref(name : "URL" , value : "http://sourceforge.net/projects/btnet/files/btnet_3_4_4_release_notes.txt/view");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bugtracker_detect.nasl");
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

## Get BugTracker Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Check for BugTracker.NET version prior to 3.4.3
if(ver = get_version_from_kb(port:port,app:"btnet"))
{
  if(version_is_less(version:ver, test_version: "3.4.3")){
      security_message(port:port);
  }
}
