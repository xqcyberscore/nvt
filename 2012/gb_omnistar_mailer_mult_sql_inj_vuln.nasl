##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_omnistar_mailer_mult_sql_inj_vuln.nasl 5912 2017-04-10 09:01:51Z teissa $
#
# Omnistar Mailer Software Multiple SQL Injection Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.802464");
  script_version("$Revision: 5912 $");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-04-10 11:01:51 +0200 (Mon, 10 Apr 2017) $");
  script_tag(name:"creation_date", value:"2012-10-04 10:42:09 +0530 (Thu, 04 Oct 2012)");
  script_name("Omnistar Mailer Software Multiple SQL Injection Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/21716/");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2012/Oct/27");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/524301/30/0/threaded");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "insight" , value : "The flaw caused by improper validation of bound vulnerable 'id'
  and 'form_id' parameters in responder, preview, pages, navlinks, contacts, register and index modules.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running Omnistar Mailer Softwar and is prone multiple
  SQL injection vulnerabilities.");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to view, add,
  modify or delete information in the back-end database and compromise the application.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Omnistar Mailer Version 7.2 and prior");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";
dir = "";
sndReq = "";
rcvRes = "";

## Get HTTP Port
port = get_http_port(default:80);

## Check for PHP support
if(!can_host_php(port:port)){
  exit(0);
}

foreach dir (make_list_unique("/mailer", "/mailertest", "/", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive request
  sndReq = http_get(item:string(dir, "/admin/index.php"), port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq, bodyonly:TRUE);

  ## Confirm application
  if("<title>OmniStar" >< rcvRes && ">Email Marketing Software<" >< rcvRes )
  {
    url = string(dir,"/users/register.php?nav_id='");

    ## Try exploit and check response to confirm vulnerability
    if(http_vuln_check(port:port,url:url,pattern:">SQL error.*error in your" +
       " SQL syntax;", check_header:TRUE, extra_check:make_list("register.php ",
       "return smtp_validation")))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);