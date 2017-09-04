###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_universal_post_mgr_plug_mult_xss.nasl 7044 2017-09-01 11:50:59Z teissa $
#
# WordPress Universal Post Manager Multiple Cross Site Scripting Vulnerabilities
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
web script or HTML in a user's browser session in the context of an affected
site.

Impact Level: Application";

tag_affected = "WordPress Universal Post Manager Plugin Version 1.0.9";

tag_insight = "The flaws are due to input validation error in 'num' parameter
in '/wp-content/plugins/universal-post-manager/template/email_screen_1.php'
and '/wp-content/plugins/universal-post-manager/template/email_screen_2.php'
and 'number' parameter in '/wp-content/plugins/universal-post-manager/templ
ate/bookmarks_slider_h.php', which is not properly sanitized before being
returned to the user.";

tag_solution = "Upgrade to version 1.1.1 or later,
 For updates refer to http://wordpress.org/extend/plugins/universal-post-manager";

tag_summary = "This host is installed with WordPress Universal Post Manager
Plugin and is prone to multiple cross-site scripting vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802018";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7044 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-01 13:50:59 +0200 (Fri, 01 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-05-02 12:20:04 +0200 (Mon, 02 May 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WordPress Universal Post Manager Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/44247");
  script_xref(name : "URL" , value : "http://seclists.org/bugtraq/2011/Apr/190");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/100592/");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/multiple_xss_in_universal_post_manager_wordpress_plugin.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

##
## The script code starts here
##

include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");
include("host_details.inc");


## Get HTTP Port
if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);

## Check host supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

## Path of Vulnerable Page
url = dir + "/wp-content/plugins/universal-post-manager/template/bookmarks_" +
            "slider_h.php?number=<script>alert(document.cookie);</script>";

## Send XSS attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"<script>alert\(document." +
                                               "cookie\);</script>", check_header:TRUE)){
  security_message(port);
}
