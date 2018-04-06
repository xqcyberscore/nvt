###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_admanager_plus_mult_xss_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# Zoho ManageEngine ADManager Plus Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
HTML and script code in a user's browser session in context of an affected site.

Impact Level: Application";

tag_affected = "ManageEngine ADManager Plus version 5.2 Build 5210";

tag_insight = "The flaw is due to an input passed to the 'domainName' parameter
in jsp/AddDC.jsp and 'operation' POST parameter in DomainConfig.do (when
'methodToCall' is set to 'save') is not properly sanitised before being returned
to the user.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Zoho ManageEngine ADManager Plus and is
prone to multiple cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802587");
  script_version("$Revision: 9352 $");
  script_cve_id("CVE-2012-1049");
  script_bugtraq_id(51893);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-02-08 12:14:53 +0530 (Wed, 08 Feb 2012)");
  script_name("Zoho ManageEngine ADManager Plus Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/47887/");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/codes/admanager_xss.txt");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/109528/ZSL-2012-5070.txt");
  script_xref(name : "URL" , value : "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2012-5070.php");

  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_require_ports("Services/www", 8080);
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = 0;
port = get_http_port(default:8080);
if(!port){
  port = 8080;
}

if(!get_port_state(port)) {
  exit(0);
}

sndReq = "";
rcvRes = "";
sndReq = http_get(item:"/home.do", port:port);
if(!isnull(sndReq))
{
  rcvRes = http_send_recv(port:port, data:sndReq);

  ## Confirm the application
  if(!isnull(rcvRes) && "<title>ManageEngine - ADManager Plus</title>" >< rcvRes)
  {
    ## Construct attack
    url = '/jsp/AddDC.jsp?domainName="><script>alert(document.cookie)</script>';

    ## Confirm exploit worked properly or not
    if(http_vuln_check(port:port, url:url, pattern:"><script>alert\(" +
                                    "document.cookie\)</script>", check_header:TRUE)){
      security_message(port:port);
    }
  }
}
