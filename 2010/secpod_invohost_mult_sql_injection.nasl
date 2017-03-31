###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_invohost_mult_sql_injection.nasl 5394 2017-02-22 09:22:42Z teissa $
#
# INVOhost Multiple SQL injection vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901112");
  script_version("$Revision: 5394 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-22 10:22:42 +0100 (Wed, 22 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-04-29 10:04:32 +0200 (Thu, 29 Apr 2010)");
  script_cve_id("CVE-2010-1336");
  script_bugtraq_id(38962);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("INVOhost Multiple SQL injection vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39095");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/38962");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11874");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to cause SQL Injection
  attack and gain sensitive information.

  Impact Level: Application");
  script_tag(name : "affected" , value : "INVOhost version 3.4 and prior.");
  script_tag(name : "insight" , value : "The flaws are caused by improper validation of user-supplied input
  via the 'id' and 'newlanguage' parameters in 'site.php', 'search' parameter in
  'manuals.php', and unspecified vectors in 'faq.php' that allows attacker to
  manipulate SQL queries by injecting arbitrary SQL code.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running INVOhost and is prone to multiple SQL
  injection vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check the php support
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/invohost", "/INVOHOST", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  res = http_get_cache(item: dir + "/site.php", port:port);

  ## Confirm the application
  if('Powered by INVOHOST' >< res)
  {
    ## Get INVOHOST Version
    ver = eregmatch(pattern:"version ([0-9.]+)", string:res);
    if(ver[1] != NULL)
    {
      ## Check for version before 3.4
      if(version_is_less_equal(version:ver[1], test_version:"3.4"))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);