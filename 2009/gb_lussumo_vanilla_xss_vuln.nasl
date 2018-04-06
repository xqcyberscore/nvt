###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lussumo_vanilla_xss_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# Vanilla 'RequestName' Cross-Site Scripting Vulnerability
#
# Authors:
# Antu Sanadi<santu@secpod.com>
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

tag_impact = "Successful exploitation could allow remote attackers to execute
arbitrary HTML and script code in a user's browser session in context of an
affect site and it result XSS attack.

Impact Level: Application.";

tag_affected = "Lussumo Vanilla 1.1.7 and prior on all running platform.";

tag_insight = "Error is due to improper sanitization of user supplied input
in the 'RequestName' parameter in '/ajax/updatecheck.php' file.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "The host is running Lussumo Vanilla and is prone to Cross-Site
Scripting Vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800623");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-06-04 10:49:28 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-1845");
  script_bugtraq_id(35114);
  script_name("Vanilla 'RequestName' Cross-Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35234");
  script_xref(name : "URL" , value : "http://gsasec.blogspot.com/2009/05/vanilla-v117-cross-site-scripting.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_lussumo_vanilla_detect.nasl");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Lussumo/Vanilla/installed");

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
include("version_func.inc");

vanillaPort = get_http_port(default:80);
if(!vanillaPort){
  exit(0);
}

vanillaVer = get_kb_item("www/" + vanillaPort + "/Lussumo/Vanilla");
if(!vanillaVer){
  exit(0);
}

vanillaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:vanillaVer);

if(!safe_checks() && vanillaVer[2] != NULL)
{
  rcvRes = http_get_cache(item:string(vanillaVer[2], "/index.php"), port:vanillaPort);

  if("Vanilla" >< rcvRes)
  {
    request = http_get(item:vanillaVer[2] + "/ajax/updatecheck.php?PostBack" +
                            "Key=1&ExtensionKey=1&RequestName=1<script>alert" +
                            "(Exploit-XSS)</script>",
                       port:vanillaPort);
    response = http_send_recv(port:vanillaPort, data:request);
    if(response =~ "HTTP/1\.. 200" && "Exploit-XSS" >< response)
    {
      security_message(vanillaPort);
      exit(0);
    }
  }
}

if(vanillaVer[1] != NULL)
{
  if(version_is_less_equal(version:vanillaVer[1], test_version:"1.1.8")){
    security_message(vanillaPort);
  }
}
