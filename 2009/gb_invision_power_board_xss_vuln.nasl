###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_invision_power_board_xss_vuln.nasl 4869 2016-12-29 11:01:45Z teissa $
#
# Invision Power Board Cross-Site Scripting Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation will let attackers execute arbitrary code in the
  context of the affected web application and can cause various web related
  attacks by point to malicious IFRAME or HTML data.
  Impact Level: Application";
tag_affected = "Invision Power Board version 2.3.1 and prior.";
tag_insight = "Improper sanitization of user supplied input in the signature data which can
  cause crafting malicious IFRAME or HTML tags to gain sensitive information
  about the web application or can cause injection of web pages to the web
  application.";
tag_solution = "Solution/Patch not available as on 09th April 2009. Information will be
  updated once the vendor supplies any updates. For further updates refer,
  http://www.invisionpower.com";
tag_summary = "The host is running Invision Power Board and is prone to Cross-Site
  Scripting Vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.800387";
CPE = "cpe:/a:invision_power_services:invision_power_board";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 4869 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 12:01:45 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-04-13 15:50:35 +0200 (Mon, 13 Apr 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2008-6565");
  script_bugtraq_id(28466);
  script_name("Invision Power Board Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/41502");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/490115");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("invision_power_board_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("invision_power_board/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");

ipbPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!ipbPort){
  exit(0);
}

if(!ipbVer = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:ipbPort))exit(0);
if(ipbVer[1] =~ "[0-9.]+")
{
  if(version_is_less_equal(version:ipbVer[1], test_version:"2.3.1")){
    security_message(ipbPort);
  }
}
