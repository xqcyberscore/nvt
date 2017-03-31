###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpmyfaq_get_xss_vuln.nasl 5122 2017-01-27 12:16:00Z teissa $
#
# phpMyFAQ GET Variable Cross-Site-Scripting Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to execute arbitrary HTML
  and script code and cause cross-site scripting attacks.
  Impact Level: Application";
tag_affected = "phpMyFAQ prior to 2.0.17 and 2.5.0 prior to 2.5.2.";
tag_insight = "This vulnerability is caused because the application does not properly sanitize
  the input passed into 'GET' parameter in 'search.php'.";
tag_solution = "Upgrade to phpMyFAQ 2.0.17 or 2.5.2
  http://www.phpmyfaq.de/download.php";
tag_summary = "This host is installed with phpMyFAQ and is prone to Cross Site
  Scripting vulnerability.";

if(description)
{
  script_id(900982);
  script_version("$Revision: 5122 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-27 13:16:00 +0100 (Fri, 27 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4040");
  script_bugtraq_id(37020);
  script_name("phpMyFAQ GET Variable Cross-Site-Scripting Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl", "gb_ms_ie_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37354");
  script_xref(name : "URL" , value : "http://www.phpmyfaq.de/advisory_2009-09-01.php");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3241");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

pmfPort = get_http_port(default:80);
if(!pmfPort){
  exit(0);
}

pmfVer = get_kb_item("www/" + pmfPort + "/phpmyfaq");
pmfVer = eregmatch(pattern:"^(.+) under (/.*)$", string:pmfVer);

if(pmfVer[1] != NULL)
{
  if(version_is_less(version:pmfVer[1],  test_version:"2.0.17")||
     version_in_range(version:pmfVer[1], test_version:"2.5", test_version2:"2.5.1")){
    security_message(pmfPort);
  }
}
