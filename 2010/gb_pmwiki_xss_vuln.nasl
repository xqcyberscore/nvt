###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pmwiki_xss_vuln.nasl 8207 2017-12-21 07:30:12Z teissa $
#
# PmWiki Table Feature 'width' Parameter Cross-site scripting vulnerability
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "PmWiki Version 2.2.15 and Prior.";
tag_insight = "The flaw is caused by improper validation of user-supplied input via the
  'width' markup while creating a table.";
tag_solution = "Upgrade to the latest version of 2.2.16 or later,
  For updates refer to http://pmwiki.org/pub/pmwiki";
tag_summary = "The host is running PmWiki and is prone to cross-site scripting
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801210");
  script_version("$Revision: 8207 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)");
  script_cve_id("CVE-2010-1481");
  script_bugtraq_id(39994);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_name("PmWiki Table Feature 'width' Parameter Cross-site scripting vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39698");
  script_xref(name : "URL" , value : "http://int21.de/cve/CVE-2010-1481-pmwiki-xss.html");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/511177/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pmwiki_detect.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get version from KB
ver = get_kb_item("www/" + port + "/PmWiki");
wikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);

if(wikiVer[1]!= NULL)
{
  ## Check for version before 2.2.16
  if(version_is_less(version: wikiVer[1], test_version: "2.2.16")){
    security_message(port);
  }
}
