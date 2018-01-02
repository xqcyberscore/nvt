###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tdiary_xss_vuln.nasl 8250 2017-12-27 07:29:15Z teissa $
#
# tDiary 'tb-send.rb' Plugin Cross-Site Scripting Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "tDiary versions prior to 2.2.3";
tag_insight = "The flaw is due to improper validation of the 'plugin_tb_url' and
  'plugin_tb_excerpt' parameters upon submission to the tb-send.rb plugin
  script.";
tag_solution = "Update to version 2.2.3 or later.
  For updates refer to http://www.tdiary.org/";
tag_summary = "The host is running tDiary and is prone to Cross-Site Scripting
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800992");
  script_version("$Revision: 8250 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-27 08:29:15 +0100 (Wed, 27 Dec 2017) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-0726");
  script_bugtraq_id(38413);
  script_name("tDiary 'tb-send.rb' Plugin Cross-Site Scripting Vulnerability");


  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_tdiary_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://www.tdiary.org/20100225.html");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/38742");
  script_xref(name : "URL" , value : "http://jvndb.jvn.jp/en/contents/2010/JVNDB-2010-000005.html");
  script_xref(name : "URL" , value : "http://tdiary.svn.sourceforge.net/viewvc/tdiary/branches/Stable-2_2/plugin/tb-send.rb?r1=3238&r2=3573");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

## Get HTTP Ports
diaryPort = get_http_port(default:80);
if(!diaryPort){
  exit(0);
}

## Get tDiary Version from KB
diaryVer = get_kb_item("www/" + diaryPort + "/tdiary");
if(isnull(diaryVer)){
  exit(0);
}

diaryVer = eregmatch(pattern:"^(.+) under (/.*)$", string:diaryVer);
if(diaryVer[1] != NULL)
{
  ## Check for version < 2.2.3
  if(version_is_less(version:diaryVer[1], test_version:"2.2.3")){
    security_message(diaryPort);
  }
}

