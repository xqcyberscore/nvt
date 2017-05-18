##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_obm_mult_vuln.nasl 5958 2017-04-17 09:02:19Z teissa $
#
# Open Business Management Multiple Vulnerabilities
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803027");
  script_version("$Revision: 5958 $");
  script_cve_id("CVE-2011-5141", "CVE-2011-5142", "CVE-2011-5143", "CVE-2011-5144",
                "CVE-2011-5145");
  script_bugtraq_id(51153);
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-17 11:02:19 +0200 (Mon, 17 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-09-18 11:33:54 +0530 (Tue, 18 Sep 2012)");
  script_name("Open Business Management Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47139");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/71924");
  script_xref(name : "URL" , value : "https://www.htbridge.com/advisory/HTB23060");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow the attacker to cause SQL
  injection attack, gain sensitive information and execute arbitrary HTML and
  script code in a user's browser session in the context of a vulnerable site.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Open Business Management (OBM) 2.4.0-rc13 and prior");
  script_tag(name : "insight" , value : "Multiple vulnerabilities due to,
  - Improper access restrictions to the 'test.php' script allowing
  attackers to obtain configuration information via a direct request to
  test.php, which calls the phpinfo function.
  - Input passed via the 'sel_domain_id' and 'action' parameters to 'obm.php'
  is not properly sanitised before being used in SQL queries.
  - Input passed via the 'tf_user' parameter to group/group_index.php and
  'tf_name', 'tf_delegation', and 'tf_ip' parameters to host/host_index.php
  is not properly sanitised before being used in SQL queries.
  - Input passed to the 'tf_name', 'tf_delegation', and 'tf_ip' parameters in
  index.php, 'login' parameter in obm.php, and 'tf_user' parameter in
  group/group_index.php is not properly sanitised before being returned
  to the user.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running Open Business Management and is prone to
  multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
dir = "";
url = "";
port = 0;

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list_unique("/", "/obm", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Confirm the application before trying exploit
  if(http_vuln_check(port:port, url: dir + "/obm.php", check_header: TRUE,
     pattern:"<title>.* OBM", extra_check: "OBM.org"))
  {
    ## Construct the Attack Request
    url = dir + '/test.php';

    ## Try attack and check the response to confirm vulnerability.
    if(http_vuln_check(port:port, url:url, check_header: TRUE,
       pattern:"<title>phpinfo()",
       extra_check: make_list('>System <', '>Configuration<', '>PHP Core<')))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);