###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_image_hosting_script_dpi_xss_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Clixint DPI Image Hosting Script Cross Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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

tag_solution = "Apply patch,
  http://www.clixint.com/support/viewtopic.php?f=3&t=542

  *****
  NOTE: Ignore this warning, if above mentioned patch is already applied.
  *****";

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary HTML
  script codes in a user's established login session into the context of an
  affected site running the vulnerable web application.
  Impact Level: Network/Application.";
tag_affected = "Image Hosting Script DPI 1.1 Final and prior on all running platform.";
tag_insight = "This flaw is due to an error in 'images.php' which doesn't verify user supplied
  input before being used via 'date' parameter.";
tag_summary = "This host is running Flashlight Free Edition and is prone to Cross Site
  Scripting Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801082");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-12-14 09:18:47 +0100 (Mon, 14 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4252");
  script_name("Clixint DPI Image Hosting Script Cross Site Scripting Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/37456");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/10300");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_image_hosting_script_dpi_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

dpiPort = get_http_port(default:80);
if(!dpiPort){
  exit(0);
}

dpiVer = get_kb_item("www/" + dpiPort + "/ImageHostingScript/DPI");
if(!dpiVer){
  exit(0);
}

dpiVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dpiVer);
if(dpiVer[1] != NULL)
{
  if(version_is_less_equal(version:dpiVer[1], test_version:"1.1.Final")){
    security_message(dpiPort);
  }
}
