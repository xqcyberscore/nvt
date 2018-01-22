###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bozotic_http_server_dos_vuln.nasl 8469 2018-01-19 07:58:21Z teissa $
#
# bozotic HTTP server Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to cause a denial of service
  via vectors related to a 'wrong code generation interaction with GCC'.
  Impact Level: Application";
tag_affected = "bozotic HTTP server (aka bozohttpd) version 20090522 through 20100512.";
tag_insight = "The flaw is due to vectors related to a 'wrong code generation
  interaction with GCC'.";
tag_solution = "Upgrade to bozotic HTTP server version 20100621 or later,
  For updates refer to http://www.eterna.com.au/bozohttpd/";
tag_summary = "This host is running bozotic HTTP server and is prone to Denial of
  Service Vulnerability";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801245");
  script_version("$Revision: 8469 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-19 08:58:21 +0100 (Fri, 19 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-08-06 17:02:44 +0200 (Fri, 06 Aug 2010)");
  script_cve_id("CVE-2010-2195");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("bozotic HTTP server Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/40737");
  script_xref(name : "URL" , value : "http://www.eterna.com.au/bozohttpd/CHANGES");
  script_xref(name : "URL" , value : "http://security-tracker.debian.org/tracker/CVE-2010-2195");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_bozotic_http_server_detect.nasl");
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
ver = get_kb_item("www/" + port + "/bozohttpd");
if(ver != NULL)
{
  ## Check for vulnerable bozohttpd versions
  if(version_in_range(version:ver, test_version:"20090522", test_version2:"20100512")) {
     security_message(port);
  }
}
