###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_php_raincheck_sql_injection_vuln.nasl 5401 2017-02-23 09:46:07Z teissa $
#
# phpRAINCHECK 'print_raincheck.php' SQL injection vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.901113");
  script_version("$Revision: 5401 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-23 10:46:07 +0100 (Thu, 23 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-05-04 09:40:09 +0200 (Tue, 04 May 2010)");
  script_cve_id("CVE-2010-1538");
  script_bugtraq_id(38521);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("phpRAINCHECK 'print_raincheck.php' SQL injection vulnerability");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/11586");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/56578");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1002-exploits/phpraincheck-sql.txt");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attacker to execute arbitrary
  SQL queries and gain sensitive information.

  Impact Level: Application");
  script_tag(name : "affected" , value : "PHP RAINCHECK 1.0.1 and prior");
  script_tag(name : "insight" , value : "The flaw is caused by improper validation of user-supplied input
  via the 'id' parameter in print_raincheck.php that allows attacker to manipulate SQL
  queries by injecting arbitrary SQL code.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running phpRAINCHECK and is prone to SQL injection
  vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check the php support
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/", "/rainchecks", "/phprainchecks", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  req = http_get(item: dir + "/settings.php",  port:port);
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);

  ## Confirm the application
  if('>phpRAINCHECK - Settings<' >< res)
  {
    ## Get phpRAINCHECK Version
    ver = eregmatch(pattern:"Version: ([0-9.]+)", string:res);
    if(ver[1])
    {
      ## Check for version before 1.0.1
      if(version_is_less_equal(version:ver[1], test_version:"1.0.1"))
      {
        security_message(port:port);
        exit(0);
      }
    }
  }
}

exit(99);