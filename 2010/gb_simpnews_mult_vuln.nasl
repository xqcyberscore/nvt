##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_simpnews_mult_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# SimpNews Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary web
  scripts and to obtain sensitive information.
  Impact Level: Application.";
tag_affected = "SimpNews Version 2.47.03 and prior.";

tag_insight = "The flaws are exists due to:
  - An error 'news.php', allow remote attackers to inject arbitrary web scripts
    via the 'layout' and 'sortorder' parameters.
  - An error in 'news.php' allows remote attackers to obtain sensitive
    information via an invalid lang parameter, which reveals the installation
    path in an error message.";
tag_solution = "Upgrade to the SimpNews version 2.48 or later,
  For updates refer to http://www.boesch-it.de/sw/simpnews.php";
tag_summary = "This host is running SimpNews and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(801391);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_cve_id("CVE-2010-2858", "CVE-2010-2859");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("SimpNews Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40501");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60244");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1007-exploits/simpnews-xss.txt");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/512271/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_simpnews_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

snPort = get_http_port(default:80);
if(!get_port_state(snPort)){
  exit(0);
}

ver = get_kb_item(string("www/", snPort, "/SimpNews"));
if(!ver){
 exit(0);
}

simpnewsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);
if(isnull(simpnewsVer[1])){
  exit(0);
}

if(version_is_less_equal(version:simpnewsVer[1], test_version:"2.47.03")){
 security_message(port:snPort);
}
