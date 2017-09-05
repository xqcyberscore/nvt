###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_arsc_mult_xss_vuln.nasl 7052 2017-09-04 11:50:51Z teissa $
#
# A Really Simple Chat Multiple XSS Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902607");
  script_version("$Revision: 7052 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-04 13:50:51 +0200 (Mon, 04 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-07-05 13:15:06 +0200 (Tue, 05 Jul 2011)");
  script_cve_id("CVE-2011-2180", "CVE-2011-2470");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("A Really Simple Chat Multiple XSS Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14050/");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/06/02/7");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2011/06/02/1");
  script_xref(name : "URL" , value : "http://www.htbridge.ch/advisory/xss_in_a_really_simple_chat_arsc.html");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to inject arbitrary
  web script or HTML by executing arbitrary scripts.

  Impact Level: Application");
  script_tag(name : "affected" , value : "A Really Simple Chat version 3.3 rc2.");
  script_tag(name : "insight" , value : "The flaws are due to improper validation of user supplied data
  in the 'arsc_link' parameter in dereferer.php and 'arsc_message' parameter in
  login.php, which allow attacker to execute arbitrary scripts.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running A Really Simple Chat and is prone to multiple
  cross site scripting vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/arsc", "/chat", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  rcvRes = http_get_cache(item:dir + "/base/index.php", port:port);

  ## Confirm the application
  if("Powered by ARSC" >< rcvRes)
  {
    attack = "/base/admin/login.php?arsc_message=<script>alert" +
             "('OpenVAS-XSS-TEST')</script>";

    ## Construct attack request
    req = http_get(item: dir + attack, port:port);
    res = http_keepalive_send_recv(port:port,data:req);

    ## Confirm the exploit
    if(res =~ "HTTP/1\.. 200" && "<script>alert('OpenVAS-XSS-TEST')</script>">< res)
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);
