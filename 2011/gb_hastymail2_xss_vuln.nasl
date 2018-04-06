##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hastymail2_xss_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Hastymail2 'background' Attribute Cross-site scripting vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary web
  script or HTML in a user's browser session in the context of an affected
  site.
  Impact Level: Application";
tag_affected = "Hastymail2 version prior to 1.01";
tag_insight = "The flaw is caused by improper validation of crafted background attribute
  within a cell in a TABLE element which allows remote attackers to inject
  arbitrary web script or HTML.";
tag_solution = "Upgrade to the Hastymail2 1.01 or later
  For updates refer to http://www.hastymail.org/blogs/News/";
tag_summary = "The host is running Hastymail2 and is prone to cross-site scripting
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801576");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_cve_id("CVE-2010-4646");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Hastymail2 'background' Attribute Cross-site scripting vulnerability");
  script_xref(name : "URL" , value : "http://www.hastymail.org/security/");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/01/05/3");
  script_xref(name : "URL" , value : "http://openwall.com/lists/oss-security/2011/01/06/14");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_hastymail2_detect.nasl");
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

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

## Get version from KB
ver = get_kb_item("www/" + port + "/Hastymail2");
if(!ver){
  exit(0);
}

hm2Ver = eregmatch(pattern:"^(.+) under (/.*)$", string:ver);
if(hm2Ver[1])
{
  ver = ereg_replace(pattern:"([A-Za-z]+)", replace:"0.", string:hm2Ver[1]);
  if(ver != NULL)
  {
    ## Check for version before 1.01
    if(version_is_less(version: ver, test_version:"1.01")){
      security_message(port);
    }
  }
}
