###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongoose_server_info_disc_vuln.nasl 8314 2018-01-08 08:01:01Z teissa $
#
# Mongoose Web Server Source Code Disclosure Vulnerability
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

tag_impact = "Successful exploitation will allow remote attackers to display the source code
  of arbitrary files instead of an expected HTML response
  Impact Level: Application";
tag_affected = "Mongoose Web Server version 2.8 and prior on windows.";
tag_insight = "The issue is due to an error within the handling of HTTP requests and
  can be exploited to disclose the source code of certain scripts (e.g. PHP) by
  appending '::$DATA' or '/' to a URI.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";
tag_summary = "The host is running Mongoose Web Server and is prone to Source Code
  Disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800412");
  script_version("$Revision: 8314 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-08 09:01:01 +0100 (Mon, 08 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-01-09 13:17:56 +0100 (Sat, 09 Jan 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-4530", "CVE-2009-4535");
  script_name("Mongoose Web Server Source Code Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://freetexthost.com/0lcsrgt3vw");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/36934");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80, 8080);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

moPort = 80;
if(!get_port_state(moPort))
{
  moPort = 8080 ;
  if(!get_port_state(moPort)){
    exit(0);
  }
}

if(!safe_checks())
{
  sndReq= http_get(item:"/index.php::$DATA", port:moPort);
  rcvRes  = http_keepalive_send_recv(port:moPort, data:sndReq);
  if(!isnull(rcvRes) && "<?php" >< rcvRes && "?>" >< rcvRes){
    security_message(moPort);
  }
}

