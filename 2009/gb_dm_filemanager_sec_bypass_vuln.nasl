###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dm_filemanager_sec_bypass_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# DM FileManager 'login.php' Security Bypass Vulnerability
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

tag_impact = "Successful exploitation will let the remote attacker execute arbitrary
  SQL commands when magic_quotes_gpc is disabled and bypass authentication
  and gain administrative access.
  Impact Level: Application";
tag_affected = "DutchMonkey, DM FileManager version 3.9.2 and prior";
tag_insight = "- Error exists when application fails to set the 'USER', 'GROUPID',
   'GROUP', and 'USERID' cookies to certain values in admin/login.php.
  - Error in 'login.php' which fails to sanitise user supplied input via
    the 'Username' and 'Password' fields.";
tag_solution = "Upgrade to DM FileManager version 3.9.10 or later,
  For updates refer to http://dutchmonkey.com";
tag_summary = "The host is running DM FileManager and is prone to Security Bypass
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800819");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-03 15:23:01 +0200 (Fri, 03 Jul 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2025", "CVE-2009-1741");
  script_bugtraq_id(35035);
  script_name("DM FileManager 'login.php' Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/8903");
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/8741");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35167");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1532");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dm_filemanager_detect.nasl");
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

dmfPort = get_http_port(default:80);
if(!dmfPort){
  exit(0);
}

dmfVer = get_kb_item("www/" + dmfPort + "/DM-FileManager");
dmfVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dmfVer);
if(dmfVer[1] != NULL)
{
  if(version_is_less_equal(version:dmfVer[1], test_version:"3.9.2")){
    security_message(dmfPort);
  }
}
