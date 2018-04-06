###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_struts_xss_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Apache Struts Cross Site Scripting Vulnerability
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

tag_impact = "Successful exploitation will let the attacker issue malicious URL or can inject
  malicious codes inside the web page contents to gain sensitive information.
  Impact Level: Application";
tag_affected = "Apache Struts version 2.0 and prior to 2.0.11.1
  Apache Struts version 2.1 and prior to 2.1.1";
tag_insight = "This flaw is due to improper sanitization of the user supplied input
  in '<s:url>' and '<s:a ...>' tag which doesn't encode the URL parameter when
  specified in the action attribute which causes XSS attacks.";
tag_solution = "Upgrade to Apache Struts version 2.1.1 or 2.0.11.1.
  http://struts.apache.org/download.cgi";
tag_summary = "This host is running Apache Struts and is prone to Cross Site Scripting
  Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800278");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6682");
  script_name("Apache Struts Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "https://issues.apache.org/struts/browse/WW-2414");
  script_xref(name : "URL" , value : "https://issues.apache.org/struts/browse/WW-2427");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_struts2_detection.nasl");
  script_require_ports("Services/www", 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

strutsPort = get_http_port(default:8080);
if(!strutsPort){
  exit(0);
}

strutsVer = get_kb_item("www/" + strutsPort + "/Apache/Struts");
strutsVer = eregmatch(pattern:"^(.+) under (/.*)$", string:strutsVer);
if(!strutsVer[1]){
  exit(0);
}

if(version_in_range(version:strutsVer[1], test_version:"2.0", test_version2:"2.0.11") ||
   version_in_range(version:strutsVer[1], test_version:"2.1", test_version2:"2.1.0")){
  security_message(strutsPort);
}
