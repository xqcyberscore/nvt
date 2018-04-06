###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_expressionengine_xss_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# ExpressionEngine CMS Cross Site Scripting Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to inject arbitrary HTML
  codes in an image by tricking the user to view a malicious profile page.
  Impact Level: Application";
tag_affected = "ExpresssionEngine versions prior to 1.6.7 on all platforms.";
tag_insight = "Inadequate validation of user supplied input to the system/index.php script
  leads to cross site attacks.";
tag_solution = "Update ExpressionEngine to version 1.6.7
  http://expressionengine.com";
tag_summary = "This host is running ExpressionEngine CMS and is prone to Cross Site
  Scripting vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800263");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-02 08:15:32 +0200 (Thu, 02 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1070");
  script_bugtraq_id(34193);
  script_name("ExpressionEngine CMS Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34379");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/49359");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/502045/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_expressionengine_detect.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("http_func.inc");
include("version_func.inc");

httpPort = get_http_port(default:80);
if(!httpPort){
  exit(0);
}

expressionVer = get_kb_item("www/" + httpPort + "/ExpEngine");
if(expressionVer == NULL){
  exit(0);
}

if(version_is_less(version:expressionVer, test_version:"1.6.7")){
  security_message(httpPort);
}
