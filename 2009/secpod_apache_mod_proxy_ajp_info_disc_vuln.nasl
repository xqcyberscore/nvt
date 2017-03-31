##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_apache_mod_proxy_ajp_info_disc_vuln.nasl 5055 2017-01-20 14:08:39Z teissa $
#
# Apache mod_proxy_ajp Information Disclosure Vulnerability
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

tag_affected = "Apache HTTP Version 2.2.11

  Workaround:
  Update mod_proxy_ajp.c through SVN Repository (Revision 767089)
  http://www.apache.org/dist/httpd/patches/apply_to_2.2.11/PR46949.diff";

tag_impact = "Successful exploitation will let the attacker craft a special HTTP POST
  request and gain sensitive information about the web server.

  Impact level: Application";

tag_insight = "This flaw is due to an error in 'mod_proxy_ajp' when handling
  improperly malformed POST requests.";
tag_solution = "Upgrade to Apache HTTP Version 2.2.15 or later
  For further updates refer, http://httpd.apache.org/download.cgi";
tag_summary = "This host is running Apache Web Server and is prone to
  Information Disclosure Vulnerability.";

if(description)
{
  script_id(900499);
  script_version("$Revision: 5055 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-20 15:08:39 +0100 (Fri, 20 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-04-30 06:40:16 +0200 (Thu, 30 Apr 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_cve_id("CVE-2009-1191");
  script_bugtraq_id(34663);
  script_name("Apache mod_proxy_ajp Information Disclosure Vulnerability");


  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("http_version.nasl", "secpod_apache_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/34827");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/50059");
  script_xref(name : "URL" , value : "http://svn.apache.org/viewvc/httpd/httpd/trunk/CHANGES?r1=766938&r2=767089");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("global_settings.inc");

httpdPort = get_http_port(default:80);
if(!httpdPort){
  exit(0);
}

version = get_kb_item("www/" + httpdPort + "/Apache");
if(version != NULL){
  if(version_is_less_equal(version:version, test_version:"2.2.11")){
    security_message(httpdPort);
  }
}
