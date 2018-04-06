##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hastymail2_sec_bypass_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Hastymail2 Session Cookie Security Bypass Vulnerability
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

tag_impact = "Successful exploitation will allow remote attackers to capture this cookie
  by intercepting its transmission within an HTTP session.
  Impact Level: Application";
tag_affected = "Hastymail2 version prior to RC 8";
tag_insight = "The flaw is due to error in handling of session cookie, which fails
  to set the secure flag for the session cookie in an HTTPS session.";
tag_solution = "Upgrade to the Hastymail2 RC 8 or later
  For updates refer to http://www.hastymail.org/blogs/News/";
tag_summary = "The host is running Hastymail2 and is prone to security bypass
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801577");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_cve_id("CVE-2009-5051");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Hastymail2 Session Cookie Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www.hastymail.org/security/");

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
    ## Check for version before RC8
    if(version_is_less(version: ver, test_version:"2.8")){
      security_message(port);
    }
  }
}
