###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_backend_open_redirection_vuln.nasl 5843 2017-04-03 13:42:51Z cfi $
#
# TYPO3 Backend Open Redirection Vulnerability
#
# Authors:
# Shashi Kiran N <nskiran@secpod.com>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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

CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804214");
  script_version("$Revision: 5843 $");
  script_bugtraq_id(42029);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-04-03 15:42:51 +0200 (Mon, 03 Apr 2017) $");
  script_tag(name:"creation_date", value:"2014-01-07 19:55:38 +0530 (Tue, 07 Jan 2014)");
  script_name("TYPO3 Backend Open Redirection Vulnerability");

tag_summary = "This host is installed with TYPO3 and is prone to open redirection
vulnerability.";

tag_vuldetect = "Send a Crafted HTTP GET request and check whether it is able to get sensitive
information.";

tag_insight = 'An error exists in Backend, which fails to sanitize "redirect"
parameter properly';

tag_impact = "Successful exploitation will allow remote attackers to conduct phishing
attacks.

Impact Level: Application";

tag_affected = "TYPO3 version before 4.1.14 and below, 4.2.0 to 4.2.13, 4.3.0 to 4.3.3 and 4.4.0";

tag_solution = "Upgrade to TYPO3 version 4.1.14, 4.2.13, 4.3.4, 4.4.1 or later,
For updates refer to, http://typo3.org/
http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2010-012";

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_xref(name : "URL" , value : "http://secunia.com/advisories/40742/");
  script_xref(name : "URL" , value : "http://typo3.org/teams/security/security-bulletins/typo3-core/typo3-sa-2010-012");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_typo3_detect.nasl");
  script_mandatory_keys("TYPO3/installed");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("url_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("gvr_apps_auth_func.inc");

## Variable initialisation
url = "";
typoPort = "";
typoLoca = "";

if(!typoPort = get_app_port(cpe:CPE)){
  exit(0);
}

if(typoLoca = get_app_location(cpe:CPE, port:typoPort))
{

  host = http_host_name(port:typoPort);
  cookie = get_typo3_login_cookie(cinstall:typoLoca, tport:typoPort, chost:host);

  if(cookie)
  {
    url = typoLoca + "/typo3/tce_file.php?redirect=http://www.example.com";

    req = string("GET ",url," HTTP/1.0\r\n",
                 "Host: " + host + "\r\n",
                 "User-Agent: " + OPENVAS_HTTP_USER_AGENT + "\r\n",
                 "Referer: http://" + host + url + "\r\n",
                 "Connection: keep-alive\r\n",
                 "Cookie: ",cookie,"\r\n",
                 "Content-Type: application/x-www-form-urlencoded\r\n\r\n");
    res = http_send_recv(port:typoPort, data:req, bodyonly:FALSE);

    get_typo3_logout(loc:typoLoca, lport:typoPort, lhost:host, lcookie:cookie);

    ## Confirm exploit worked by checking the response
    if(res && res =~ "HTTP/1.. 302" && "Expires: 0" >< res &&
       "Location: http://www.example.com" >< res)
    {
      security_message(typoPort);
      exit(0);
    }
  }
}
