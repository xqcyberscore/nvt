###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_moinmoin_wiki_sys_argv_info_disc_vuln.nasl 8207 2017-12-21 07:30:12Z teissa $
#
# MoinMoin Wiki 'sys.argv' Information Disclosure Vulnerability
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

tag_impact = "Successful exploitation will allow remote attackers to obtain sensitive
  information.
  Impact Level: Application";
tag_affected = "MoinMoin Wiki version 1.9 before 1.9.1 on all platforms.";
tag_insight = "The flaw exists while handling sys.argv parameter when the GATEWAY_INTERFACE
  environment variable is set, which allows remote attackers to obtain
  sensitive information via unspecified vectors.";
tag_solution = "Upgrade to MoinMoin Wiki 1.9.1 or later,
  For updates refer to http://moinmo.in/MoinMoinDownload";
tag_summary = "This host is running MoinMoin Wiki and is prone to Information
  Disclosure vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800171");
  script_version("$Revision: 8207 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-21 08:30:12 +0100 (Thu, 21 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-05 10:09:57 +0100 (Fri, 05 Mar 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_bugtraq_id(38116);
  script_cve_id("CVE-2010-0667");
  script_name("MoinMoin Wiki 'sys.argv' Information Disclosure Vulnerability");


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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38242");
  script_xref(name : "URL" , value : "http://marc.info/?l=oss-security&m=126625972814888&w=2");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/01/21/6");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/02/15/2");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get the port where MoinMoin Wiki application is running
moinWikiPort = get_http_port(default:80);
if(!moinWikiPort){
  exit(0);
}

## Get MoinMOin Wiki Version from KB
moinWikiVer = get_kb_item("www/" + moinWikiPort + "/moinmoinWiki");
moinWikiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:moinWikiVer);

if(moinWikiVer[1] != NULL)
{
  ## Check for version > 1.9, < 1.9.1
  if(version_in_range(version:moinWikiVer[1], test_version:"1.9",
                                              test_version2:"1.9.0")){
    security_message(moinWikiPort);
  }
}
