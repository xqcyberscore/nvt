###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_wiki_su_list_unspecified_vuln.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# MoinMoin Wiki Superuser Lists Unspecified Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Impact is currently unknown.
  Impact Level: Application";
tag_affected = "MoinMoin Wiki version 1.5.x through 1.7.x, 1.8.x before 1.8.7,
  and 1.9.x before 1.9.2 on all platforms.";
tag_insight = "Unspecified error is present related to configurations that have a non-empty
  superuser list, when 'xmlrpc', 'SyncPages' actions are enabled or OpenID
  configured.";
tag_solution = "Upgrade to MoinMoin Wiki 1.8.7 or 1.9.2,
  For updates refer to http://moinmo.in/MoinMoinDownload";
tag_summary = "This host is running MoinMoin Wiki and is prone to unspecified
  vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800173");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(38023);
  script_cve_id("CVE-2010-0668");
  script_name("MoinMoin Wiki Superuser Lists Unspecified Vulnerability");
  script_xref(name : "URL" , value : "http://moinmo.in/SecurityFixes");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38444");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56002");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0266");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/02/15/2");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_moinmoin_wiki_detect.nasl");
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

## Get the port where MoinMoin Wiki application is running
moinWikiPort = get_http_port(default:80);
if(!moinWikiPort){
  exit(0);
}

## Get MoinMoin Wiki Version from KB
moinWikiVer = get_kb_item("www/" + moinWikiPort + "/moinmoinWiki");
moinWikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:moinWikiVer);

if(moinWikiVer[1] != NULL)
{
  ## Check for version 1.5.x through 1.7.x, 1.8 through 1.8.7
  ## 1.9 before 1.9.2
  if(version_in_range(version:moinWikiVer[1], test_version:"1.5",
                                              test_version2:"1.7.9") ||
     version_in_range(version:moinWikiVer[1], test_version:"1.8",
                                              test_version2:"1.8.6") ||
     version_in_range(version:moinWikiVer[1], test_version:"1.9",
                                              test_version2:"1.9.1")) {
    security_message(moinWikiPort);
  }
}
