###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_moinmoin_wiki_acl_sec_bypass_vuln.nasl 8457 2018-01-18 07:58:32Z teissa $
#
# MoinMoin Wiki ACL Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to bypass intended access
  restrictions by requesting an item.
  Impact Level: Application";
tag_affected = "MoinMoin Wiki version 1.7.x before 1.7.3 and 1.8.x before 1.8.3";
tag_insight = "The flaw is due to error in checking the parent ACLs in certain
  inappropriate circumstances during processing of hierarchical ACLs.";
tag_solution = "Upgrade to MoinMoin Wiki 1.7.3 or 1.8.3,
  For updates refer to http://moinmo.in/MoinMoinDownload";
tag_summary = "This host is running MoinMoin Wiki and is prone to security bypass
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902154");
  script_version("$Revision: 8457 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-18 08:58:32 +0100 (Thu, 18 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2009-4762");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("MoinMoin Wiki Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://moinmo.in/SecurityFixes");
  script_xref(name : "URL" , value : "http://hg.moinmo.in/moin/1.8/rev/897cdbe9e8f2");
  script_xref(name : "URL" , value : "http://hg.moinmo.in/moin/1.7/rev/897cdbe9e8f2");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2010/0266");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
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

moinWikiPort = get_http_port(default:80);
if(!moinWikiPort){
  exit(0);
}

## Get MoinMoin Wiki Version from KB
moinWikiVer = get_kb_item("www/" + moinWikiPort + "/moinmoinWiki");
moinWikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:moinWikiVer);

if(moinWikiVer[1] != NULL)
{
  ## Check for version 1.7.x through 1.7.2, 1.8 through 1.8.2
  if(version_in_range(version:moinWikiVer[1], test_version:"1.7", test_version2:"1.7.2") ||
     version_in_range(version:moinWikiVer[1], test_version:"1.8", test_version2:"1.8.2")){
    security_message(moinWikiPort);
  }
}
