###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_wiki_user_prof_unspecified_vuln.nasl 8274 2018-01-03 07:28:17Z teissa $
#
# MoinMoin Wiki User Profile Unspecified Vulnerability
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
tag_affected = "MoinMoin Wiki version before 1.8.7 and 1.9 before 1.9.2 on all platforms.";
tag_insight = "An unspecified error exists in MoinMoin Wiki related to sanitization of
  user profiles.";
tag_solution = "Upgrade to MoinMoin Wiki 1.8.7 or 1.9.2,
  For updates refer to http://moinmo.in/MoinMoinDownload";
tag_summary = "This host is running MoinMoin Wiki and is prone to unspecified
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800172");
  script_version("$Revision: 8274 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-03 08:28:17 +0100 (Wed, 03 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(38023);
  script_cve_id("CVE-2010-0669");
  script_name("MoinMoin Wiki User Profile Unspecified Vulnerability");
  script_xref(name : "URL" , value : "http://moinmo.in/SecurityFixes");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38444");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/02/21/2");
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
  ## Check for version before 1.8.7 or 1.9 before 1.9.2
  if(version_is_less(version:moinWikiVer[1], test_version:"1.8.7") ||
     version_in_range(version:moinWikiVer[1], test_version:"1.9",
                                             test_version2:"1.9.1")){
    security_message(moinWikiPort);
  }
}
