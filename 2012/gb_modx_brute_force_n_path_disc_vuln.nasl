###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_modx_brute_force_n_path_disc_vuln.nasl 3046 2016-04-11 13:53:51Z benallard $
#
# MODx Brute Force and Path Disclosure Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802495");
  script_version("$Revision: 3046 $");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2016-04-11 15:53:51 +0200 (Mon, 11 Apr 2016) $");
  script_tag(name:"creation_date", value:"2012-11-21 10:48:20 +0530 (Wed, 21 Nov 2012)");
  script_name("MODx Brute Force and Path Disclosure Vulnerabilities");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Nov/142");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/118240/modx-brutedisclose.txt");

  script_summary("Check for path disclosure vulnerability in MODx CMS");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow the attacker to obtain
  sensitive information that could aid in further attacks.

  Impact Level: Application");
  script_tag(name : "affected" , value : "MODx CMF version 2.x (Revolution)
  MODx CMS version 1.x (Evolution)");
  script_tag(name : "insight" , value : "- In login form (manager/index.php) there is no reliable
  protection from brute force attacks.
  - Insufficient error checking, allows remote attackers to obtain sensitive
  information via a direct request to a .php file, which reveals the
  installation path in an error message.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is installed with MODx and is prone to brute force and
  path disclosure vulnerabilities.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";

## Get HTTP port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list_unique("/modx", "/cmf", "/",  cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";
  url = dir + "/manager/index.php";

  ## Confirm the application
  if(http_vuln_check(port:port, url:url, pattern:">MODx CMF Manager Login<",
     check_header:TRUE, extra_check:make_list('>MODx<', 'ManagerLogin')))
  {
    ## Construct the attack request
    url = dir + '/manager/includes/browsercheck.inc.php';

    ## Confirm the vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"Failed opening" +
       " required 'MODX_BASE_PAT.*browsercheck.inc.php", check_header:TRUE,
       extra_check:make_list('phpSniff.class.php','MODX_BASE_PATH')))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);